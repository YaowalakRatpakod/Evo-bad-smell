# views.py
from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from django.http import JsonResponse
from django.http import HttpResponseNotAllowed
from django.shortcuts import render
from rest_framework.authentication import TokenAuthentication

from .pusher import pusher_client
from .models import User
from .models import ConsultationRequest
from .models import CompletedConsultation
from .serializers import CreateUserSerializer
from .serializers import ConsultationRequestSerializer
from .serializers import CompletedConsultationSerializer

import json
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required


class UserListView(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = CreateUserSerializer
    permission_classes = [IsAuthenticated]  # ต้อง login เพื่อเข้าถึง API

    # def list(self, request, *args, **kwargs):
    #     queryset = self.get_queryset()
    #     serializer = self.get_serializer(queryset, many=True)
    #     return Response(serializer.data)

    def get_object(self):
        return self.request.user
    

# ค่า Fullname แบบ dropdown ไม่จำเป็นลบได้
class FullnameDropdownView(View):
    def get(self, request, *args, **kwargs):
        users = User.objects.values('full_name')
        # serializers = UserSerializer(users, many=True)
        return JsonResponse(list(users), safe=False)


class ConsultationRequestCreateView(APIView):
    # queryset = ConsultationRequest.objects.all()  # กำหนด queryset เพื่อให้ CreateAPIView ทำงานได้
    # serializer_class = ConsultationRequestSerializer
    # authentication_classes = []
    permission_classes = [IsAuthenticated]

    # def get_serializer_class(self):
    #     return ConsultationRequestSerializer

    def post(self, request, *args, **kwargs):
        # ดึงข้อมูลผู้ใช้ที่ล็อกอิน
        # user = request.user
        request.data['submission_date'] = request.data.get('submission_date', None)
        #สร้าง serializer และกำหนดค่าให้กับ full_name
        serializer = ConsultationRequestSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save(user=request.user)  # ใช้ request.user เพื่อกำหนดผู้ใช้ที่สร้างคำขอ
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#API ENDPOINT ของการ์ดคำถาม
class ConsultationRequestListView(View):
    def get(self,request):
        data = ConsultationRequest.objects.values()
        return JsonResponse({'data':list(data)}, safe=False)

#API ENDPOINT ของรายการที่เสร็จวิ้น
class CompletedConsultationList(generics.ListAPIView):
    queryset = CompletedConsultation.objects.all()
    serializer_class = CompletedConsultationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return CompletedConsultation.objects.filter(user=user)
    
#API ENDPOINT ของสถิติ
def statistics_view(request):
    #ดึงข้อมูลสถิติ
    completed_count = CompletedConsultation.objects.count()

    # ส่งข้อมูลสถิติกลับเป็น JSON
    data = {
        'completed_count': completed_count,
    }

    return JsonResponse(data)

# API_ENDPOINT ของ message
class MessageAPIView(APIView):
    def post(self, request):
        pusher_client.trigger('users', 'message', {
            'username': request.data['username'],
            'message': request.data['message']
            })
        
        return Response([])
    

#API_ENDPOINT
@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')

        user = authenticate(request, username=email, password=password)

        if user is not None:
            login(request, user)
            return JsonResponse({'success': True, 'message': 'Login successful'})
        else:
            return JsonResponse({'success': False, 'message': 'Login failed'})
    else:
        return JsonResponse({'success': False, 'message': 'Invalid request method'})

@login_required
def user_data(request):
    if request.method == 'GET':
        user = request.user
        return JsonResponse({'full_name': user.full_name, 'tel': user.tel, 'email': user.email})
    else:
        return HttpResponseNotAllowed(['GET'])
    
def user_consultation_requests(request):
    if request.user.is_authenticated:
        user = request.user
        # ดึงข้อมูลรายการขอคำปรึกษาของผู้ใช้
        consultation_requests = ConsultationRequest.objects.filter(user=user)
        return JsonResponse({'consultation_requests': list(consultation_requests)})
    else:
        return JsonResponse({'error': 'User is not authenticated'})
# def create_consultation_request(request):
#     if request.method == 'POST':
#         user = request.user
#         # ให้ full_name, tel, email มีค่าจากข้อมูลของผู้ใช้
#         consultation_request = ConsultationRequest.objects.create(
#             user=user,
#             full_name=user.full_name,
#             tel=user.tel,
#             email=user.email,
#             # ส่วนอื่น ๆ ของ consultation_request
#         )
#         # ต่อไปคุณสามารถทำสิ่งที่คุณต้องการกับ consultation_request ที่ถูกสร้าง
#         return JsonResponse({'success': True, 'message': 'Consultation request created successfully'})
#     else:
#         return HttpResponseNotAllowed(['POST'])
    
#test ตัว create ของรายการใหม่อีกรอบ
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_consultation_request(request):
    # สร้าง instance ใหม่ของ serializer ด้วยข้อมูลจาก request.data
    serializer = ConsultationRequestSerializer(data=request.data)
    if serializer.is_valid():
        # ใช้ save() เพื่อสร้าง instance ใหม่ของ ConsultationRequest
        # โดยกำหนดผู้ใช้ (user) โดยใช้ request.user
        serializer.save(user=request.user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])        
def user_consultation_requests(request):
    consultation_requests = ConsultationRequest.objects.filter(user=request.user)
    serializer = ConsultationRequestSerializer(consultation_requests, many=True)
    return Response(serializer.data)

