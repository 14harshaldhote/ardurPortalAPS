from django.test import TestCase, RequestFactory
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.contrib.auth.models import User
from django.contrib.sessions.middleware import SessionMiddleware
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from aps.models import Attendance, UserSession, Leave
from django.contrib.auth.signals import user_logged_in, user_logged_out


User = get_user_model()

class UserSessionTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def create_session(self, ip_address='203.0.113.1'):
        """Helper method to create a UserSession"""
        session_key = f'test_session_{timezone.now().timestamp()}'  # Ensure unique session key
        return UserSession.objects.create(
            user=self.user,
            session_key=session_key,
            ip_address=ip_address,
            login_time=timezone.now()
        )


    def test_new_session_creation(self):
        """Test creating a new user session"""
        session = self.create_session()
        self.assertEqual(session.user, self.user)
        self.assertEqual(session.location, 'Office')
        self.assertIsNone(session.logout_time)
        self.assertEqual(session.idle_time, timedelta(0))

    def test_home_location_detection(self):
        """Test working from home location detection"""
        session = self.create_session(ip_address='192.168.1.1')
        self.assertEqual(session.location, 'Home')

    def test_office_location_detection(self):
        """Test office location detection"""
        session = self.create_session(ip_address='203.0.113.1')
        self.assertEqual(session.location, 'Office')

    def test_session_idle_time_calculation(self):
        """Test idle time calculation"""
        session = self.create_session()

        # Simulate 5 minutes of inactivity
        with patch('django.utils.timezone.now') as mock_now:
            initial_time = timezone.now()
            mock_now.return_value = initial_time + timedelta(minutes=5)
            session.update_activity()

        self.assertGreater(session.idle_time, timedelta(minutes=4))


    def test_session_working_hours_calculation(self):
        """Test working hours calculation"""
        session = self.create_session()
        
        # Simulate 2 hours of work with 15 minutes idle
        with patch('django.utils.timezone.now') as mock_now:
            initial_time = timezone.now()
            # Add some activity after 1 hour
            mock_now.return_value = initial_time + timedelta(hours=1)
            session.update_activity()
            
            # End session after 2 hours
            mock_now.return_value = initial_time + timedelta(hours=2)
            session.end_session()
        
        self.assertGreater(session.working_hours, timedelta(hours=1, minutes=45))
        self.assertLess(session.working_hours, timedelta(hours=2))

class AttendanceTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.today = timezone.now().date()

    def create_attendance(self, date=None, status='Pending'):
        """Helper method to create attendance record"""
        if date is None:
            date = self.today
        return Attendance.objects.create(
            user=self.user,
            date=date,
            status=status
        )

    def create_user_session(self, login_time=None, logout_time=None, location='Office'):
        """Helper method to create user session"""
        if login_time is None:
            login_time = timezone.now()
        return UserSession.objects.create(
            user=self.user,
            session_key='test_session',
            login_time=login_time,
            logout_time=logout_time,
            location=location
        )

    def test_weekend_attendance(self):
        """Test attendance marking for weekends"""
        # Create attendance for a Saturday
        saturday = self.today + timedelta(days=(5 - self.today.weekday() + 7) % 7)
        attendance = self.create_attendance(date=saturday)
        attendance.calculate_attendance()
        self.assertEqual(attendance.status, 'Weekend')

    def test_leave_attendance(self):
        """Test attendance marking for leave days"""
        leave = Leave.objects.create(
            user=self.user,
            start_date=self.today,
            end_date=self.today,
            leave_type='Paid Leave'
        )
        attendance = self.create_attendance()
        attendance.leave_request = leave
        attendance.calculate_attendance()
        self.assertEqual(attendance.status, 'On Leave')

    def test_work_from_home_detection(self):
        """Test work from home detection"""
        attendance = self.create_attendance()
        self.create_user_session(location='Home')
        attendance.calculate_attendance()
        self.assertEqual(attendance.status, 'Work From Home')

    def test_present_status(self):
        """Test present status calculation"""
        attendance = self.create_attendance()
        login_time = timezone.now()
        self.create_user_session(
            login_time=login_time,
            logout_time=login_time + timedelta(hours=8)
        )
        attendance.calculate_attendance()
        self.assertEqual(attendance.status, 'Present')

    def test_absent_status(self):
        """Test absent status for past dates"""
        yesterday = self.today - timedelta(days=1)
        attendance = self.create_attendance(date=yesterday)
        attendance.calculate_attendance()
        self.assertEqual(attendance.status, 'Absent')

    def test_multiple_sessions_calculation(self):
        """Test attendance calculation with multiple sessions"""
        attendance = self.create_attendance()
        base_time = timezone.now()
        
        # Create morning session
        self.create_user_session(
            login_time=base_time,
            logout_time=base_time + timedelta(hours=4)
        )
        
        # Create afternoon session
        self.create_user_session(
            login_time=base_time + timedelta(hours=5),
            logout_time=base_time + timedelta(hours=9)
        )
        
        attendance.calculate_attendance()
        self.assertEqual(attendance.status, 'Present')
        self.assertEqual(attendance.total_hours, timedelta(hours=8))

    def test_partial_day_calculation(self):
        """Test attendance calculation for partial day"""
        attendance = self.create_attendance()
        base_time = timezone.now()
        
        # Create a 4-hour session
        self.create_user_session(
            login_time=base_time,
            logout_time=base_time + timedelta(hours=4)
        )
        
        attendance.calculate_attendance()
        self.assertEqual(attendance.status, 'Present')
        self.assertEqual(attendance.total_hours, timedelta(hours=4))

class AttendanceSignalsTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_login_signal(self):
        """Test attendance creation on login"""
        request = self.factory.get('/login')
        request.user = self.user
        
        # Add session to request
        middleware = SessionMiddleware(lambda x: None)
        middleware.process_request(request)
        request.session.save()
        
        # Trigger login signal
        user_logged_in.send(sender=self.user.__class__, request=request, user=self.user)
        
        # Check attendance was created
        attendance = Attendance.objects.filter(user=self.user, date=timezone.now().date()).first()
        self.assertIsNotNone(attendance)

    def test_logout_signal(self):
        """Test attendance update on logout"""
        # Create initial attendance and session
        attendance = Attendance.objects.create(
            user=self.user,
            date=timezone.now().date(),
            status='Present'
        )
        
        session = UserSession.objects.create(
            user=self.user,
            session_key='test_session',
            login_time=timezone.now()
        )
        
        request = self.factory.get('/logout')
        request.user = self.user
        request.session = MagicMock()
        request.session.session_key = 'test_session'
        
        # Trigger logout signal
        user_logged_out.send(sender=self.user.__class__, request=request, user=self.user)
        
        # Refresh attendance from db
        attendance.refresh_from_db()
        session.refresh_from_db()
        
        self.assertIsNotNone(session.logout_time)
        self.assertIsNotNone(attendance.clock_out_time)