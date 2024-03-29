#ใช้ในการจัดการการสร้างผู้ใช้และผู้ดูแลระบบ (superuser). 
from django.contrib.auth.base_user import BaseUserManager
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.utils.translation import gettext_lazy as _

# code here ..
class CustomUserManager(BaseUserManager):

    def email_validator(self, email):
        try:
            validate_email(email)

        except ValidationError:
            raise ValueError(_("You must provide a valid email"))
        
    def create_user(self, full_name, tel, email, password=None, **extra_fields):
        if not full_name:
            raise ValueError(_("Users must submit a Full name"))
        
        if email:
            email = self.normalize_email(email)
            self.email_validator(email)
        else:
            raise ValueError(_("Base User: and email address is required"))
        
        user = self.model(
            full_name = full_name,
            tel       = tel,
            email     = email,
            **extra_fields
        )

        user.set_password(password)
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)

        user.save(using=self._db)

        return user
    
    def create_superuser(self, full_name, tel, email, password=None, **extra_fields): 
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superusers must have is_superuser=True'))
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True'))
        
        if not password:
            raise ValueError(_('Superusers must have a password'))

        if email:
            email = self.normalize_email(email)
            self.email_validator(email)
        else:
            raise ValueError(_("Admin User: and email address is required"))
        
        user = self.create_user(
            full_name=full_name, 
            tel=tel, 
            email=email, 
            password=password, 
            **extra_fields)

        user.save()

        return user