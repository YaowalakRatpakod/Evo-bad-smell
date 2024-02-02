from django.urls import path
# from .views import get_user
from .views import ConsultationRequestCreateView
from .views import FullnameDropdownView
# from .views import ConsultationRequestListView
from .views import user_consultation_requests
from .views import statistics_view

from .views import MessageAPIView

urlpatterns = [
    #  path('v1/auth/user/', get_user, name='get_user'),
    path('v1/consultation-request/create/', ConsultationRequestCreateView.as_view(), name='consultation-request-create'),
    path('v1/fullname-dropdown/', FullnameDropdownView.as_view(), name='fullname-dropdown'),
    #  path('consultation-request/list/', ConsultationRequestListView.as_view(), name='consultation_request_list'),
    path('statistics/', statistics_view, name='statistics-view'),
    #  path('dropdown/', dropdown_data, name='dropdown_data'),
    path('messages', MessageAPIView.as_view()),
    path('user-consultation-requests/', user_consultation_requests, name='user-consultation-requests'),


    # เพิ่ม URL pattern อื่น ๆ ตามที่ต้องการ
]
