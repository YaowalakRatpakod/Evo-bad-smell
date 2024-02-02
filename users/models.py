from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils.translation import gettext_lazy as _
from .managers import CustomUserManager
from django.contrib.auth.models import User
from django.utils import timezone

# Create your models here.


class User(AbstractBaseUser, PermissionsMixin):
    full_name= models.CharField(_('Full Name'), max_length=100)
    tel=models.CharField(_('Tel'),max_length=10)
    email = models.EmailField(_("email address"), max_length=254, unique=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['full_name', 'tel'] 

    objects = CustomUserManager()

    class Meta:
        verbose_name = _('User')
        verbose_name_plural = _('Users')
    
    def __str__(self):
        return self.full_name
    
    @property
    def get_full_name(self):
        return f"{self.full_name}"
    
class ConsultationRequest(models.Model):

    TOPIC_CODE = {
        "ADM01": "ADM01",
        "ADM02": "ADM02",
        "ADM03": "ADM03",
        "REG04": "REG04",
        "REG05": "REG05",
        "UP01": "UP01",
        "UP02": "UP02",
        "UP03": "UP03",
        "UP03.1": "UP03.1",
        "UP05": "UP05",
        "UP06": "UP06",
        "UP07": "UP07",
        "UP08": "UP08",
        "UP09": "UP09",
        "UP10": "UP10",
        "UP11": "UP11",
        "UP12": "UP12",
        "UP13": "UP13",
        "UP14": "UP14",
        "UP17": "UP17",
        "UP18": "UP18",
        "UP20.1": "UP20.1",
        "UP24": "UP24",
        "UP25": "UP25",
        "UP29": "UP29",
        "UP30": "UP30",
    }
    TOPIC_TITLE = {
        "ADM01": "สมัครโครงการรับนิสิตกลับเข้าศึกษาในมหาวิทยาลัยพะเยา (รีรหัส)",
        "ADM02": "คำร้องขอส่งใบรับรองแพทย์",
        "ADM03": "คำร้องส่งข้อมูลผลการสอบ TPAT5 ความถนัดครุศาสตร์-ศึกษาศาสตร์",
        "REG04": "คำร้องขอรับผลการเรียนรายวิชาในหมวดวิชาศึกษาทั่วไป",
        "REG05": "คำร้องขอพัฒนาผลการเรียนรายวิชาในหมวดวิชาศึกษาทั่วไป",
        "UP01": "คำร้องทั่วไป",
        "UP02": "คำร้องขอใบรับรอง",
        "UP03": "คำร้องขอใบรายงานผลการศึกษา (Transcript)",
        "UP03.1": "คำร้องขอใบรายงานผลการศึกษา (Digital Transcript)",
        "UP05": "คำร้องขอเพิ่มรายวิชาหลังกำหนด",
        "UP06": "คำร้องขอลงทะเบียนเรียนมากกว่า/น้อยกว่าเกณฑ์",
        "UP07": "คำร้องขออนุมัติเทียบรายวิชา",
        "UP08": "คำร้องขอถอนรายวิชา โดยได้รับอักษร W",
        "UP09": "คำร้องขอเทียบโอนรายวิชา",
        "UP10": "คำร้องขอย้ายคณะ/หลักสูตร/แผนการเรียน",
        "UP11": "คำร้องขอเปลี่ยนชื่อ ชื่อสกุล ยศ และอื่นๆ",
        "UP12": "คำร้องขอลาพักการศึกษา",
        "UP13": "คำร้องขอลาออกจากการศึกษา",
        "UP14": "คำร้องขอลงทะเบียนเรียนพร้อมฝึกงาน/การศึกษาอิสระ/วิทยานิพนธ์",
        "UP17": "คำร้องขอผ่อนผันการชำระค่าลงทะเบียนเรียน",
        "UP18": "คำร้องขอผ่อนผันการชำระค่าลงทะเบียนเรียน",
        "UP20.1": "คำร้องยื่นความประสงค์ขอลงทะเบียนเรียนรายวิชา",
        "UP24": "คำร้องขอสำเร็จการศึกษา",
        "UP29": "คำร้องขอยื่นสำเร็จการศึกษาล่าช้ากว่ากำหนด",
        "UP30": "คำร้องขอถอนรายวิชาศึกษาทั่วไป (GE-Online)",
    }

    STATUS_CHOICES = [
        ('Pending', 'รอดำเนินการ'),
        ('Processing', 'กำลังดำเนินการ'),
        ('Completed', 'เสร็จสิ้น'),
        ('Appointment', 'การนัดหมาย'),
        ]
    
    full_name = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='consultation_requests',  # เพิ่มบรรทัดนี้
        null=True,
        default=None
    )    # tel = models.CharField(User)
    topic_code = models.CharField(max_length=10, choices=TOPIC_CODE)  # แก้ไขตามความเหมาะสม
    topic_title = models.CharField(max_length=10, choices=TOPIC_TITLE)
    submission_date = models.DateTimeField(null=True, blank=True, default=timezone.now)
    received_date = models.DateTimeField(null=True, blank=True, default=timezone.now)
    details = models.TextField()
    document = models.ImageField(upload_to='documents/', null=True, blank=True) # เผื่อไว้อัพโหลดรูป
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='pending')

    user = models.ForeignKey(User, on_delete=models.CASCADE, default=False)


# คลังเก็บรายการคำขอที่เสร็จสิ้นแล้ว
class CompletedConsultation(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    topic_code = models.CharField(max_length=20)
    topic_title = models.CharField(max_length=255)
    submission_date = models.DateTimeField()
    details = models.TextField()
    document = models.ImageField(upload_to='completed_consultations/', null=True, blank=True)

    def __str__(self):
        return f"{self.user.full_name} - {self.topic_title}"