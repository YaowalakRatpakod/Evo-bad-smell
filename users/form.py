# form การสร้างผู้ใช้ใหม่และการแก้ไขข้อมูลผู้ใช้

from django.contrib.auth.forms import UserChangeForm, UserCreationForm
from .models import User

class CustomUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = User
        fields = ['full_name','tel','email']
        error_class = "error"

class CustomUserChangeForm(UserChangeForm):
    class Meta(UserChangeForm.Meta):
        model = User
        fields = ['full_name','tel','email']
        error_class = "error"
