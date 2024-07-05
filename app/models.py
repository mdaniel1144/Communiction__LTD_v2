from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone

class UserManager(BaseUserManager):
    def create_user(self, email, firstname, lastname, birthday, password=None):
        """
        Creates and saves a User with the given email, first name, last name, birthday, and password.
        """
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, firstname=firstname, lastname=lastname, birthday=birthday)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, firstname, lastname, birthday, password=None):
        """
        Creates and saves a superuser with the given email, first name, last name, birthday, and password.
        """
        user = self.create_user(email, firstname, lastname, birthday, password)
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

class User(AbstractBaseUser, PermissionsMixin):
    firstname = models.CharField(max_length=255)
    lastname = models.CharField(max_length=255)
    birthday = models.DateField()
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='custom_user_set',
        blank=True,
        help_text=('The groups this user belongs to. A user will get all permissions granted to each of their groups.'),
        verbose_name=('groups')
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='custom_user_set',
        blank=True,
        help_text=('Specific permissions for this user.'),
        verbose_name=('user permissions')
    )

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['firstname', 'lastname', 'birthday']

    def __str__(self):
        return f"Email: {self.email}"

    def GetFullName(self):
        return f"{self.firstname} {self.lastname}"
    
    def GetAll(self):
        return f"User: FirstName: {self.firstname}, LastName: {self.lastname}, Birthday: {self.birthday}, Email: {self.email}"

  
class Customer(models.Model):
    
    CHOICES = [
        ('Manager', 'Manager'),
        ('Assistant', 'Assistant'),
        ('Department Manager', 'Department Manager'),
        ('CEO', 'CEO'),
        ('Counselor', 'Counselor'),
        ('Employee', 'Employee'),
    ]
    firstname = models.CharField(max_length=255)
    lastname = models.CharField(max_length=255)
    birthday = models.DateField()
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=255)
    city = models.CharField(max_length=255)
    street = models.CharField(max_length=255)
    date_join = models.DateField(default=timezone.now)
    job = models.CharField(max_length=20, choices=CHOICES, default='option1')

    
    def __str__(self): 
        return f"Email: {self.email}"
    

class HistoryPassword(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    password = models.TextField(max_length=255)
    date_insert = models.DateTimeField(default=timezone.now)