from django.contrib.auth import get_user_model
from djoser.serializers import UserCreateSerializer
from rest_framework import serializers

from .models import ConsultationRequest
from .models import User
from .models import CompletedConsultation



User = get_user_model()

class CreateUserSerializer(UserCreateSerializer):
    class Meta(UserCreateSerializer.Meta):
        model = User
        fields = ['id', 'email', 'full_name', 'password']
        is_active = serializers.BooleanField(default=True)

class UserSerializer(serializers.ModelSerializer):
    # id = serializers.IntegerField()
    class Meta:
        model = User
        fields = ['id', 'full_name']

# สร้างคำขอปรึกษา
class ConsultationRequestSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)  # เพิ่ม UserSerializer เข้าไป

    class Meta:
        model = ConsultationRequest
        fields = '__all__'

    def create(self, validated_data):
    # ลองดึงข้อมูล user จาก validated_data
        user_data = validated_data.get('user', None)
        
        # ตรวจสอบว่า 'status' มีอยู่ใน validated_data หรือไม่
        if 'status' in validated_data:
            status_data = validated_data['status']
        else:
            # ถ้าไม่มีให้ใช้ค่า default หรือให้เกิดข้อผิดพลาดขึ้นอยู่กับการออกแบบของระบบ
            status_data = None  # หรือสามารถกำหนดค่า default ได้ตามต้องการ
            
        # ตรวจสอบว่ามีข้อมูล user หรือไม่
        if user_data:
            # หา instance ของ User จากข้อมูลที่ดึงมา
            user_instance = self.context['request'].user
            serializer = ConsultationRequestSerializer(data=validated_data, context=self.context)
            # user_instance = User.objects.get(full_name=user_data['full_name'])
            # ใช้ instance ของ User ในการสร้าง ConsultationRequest
            consultation_request = ConsultationRequest.objects.create(
                # user=user_instance,
                user=self.context['request'].user,
                topic_code=validated_data['topic_code'],
                topic_title=validated_data['topic_title'],
                submission_date=validated_data['submission_date'],
                details=validated_data['details'],
                document=validated_data.get('document', None),
                status=status_data
                )
            return consultation_request
        else:
            # ถ้าไม่มีข้อมูล user ให้ทำการ raise exception หรือทำอย่างไรตามที่เหมาะสม
            raise serializers.ValidationError("User data is missing in the request.")

    
# รายการที่เสร็จสิ้น
class CompletedConsultationSerializer(serializers.ModelSerializer):
    class Meta:
        model = CompletedConsultation
        fields = '__all__'