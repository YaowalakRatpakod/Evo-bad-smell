# middleware.py

from django.http import JsonResponse

class AccessTokenMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if 'HTTP_AUTHORIZATION' not in request.META:
            return JsonResponse({'error': 'Access Token is missing'}, status=401)

        # ตรวจสอบว่า Access Token ถูกส่งมาในรูปแบบที่ถูกต้องหรือไม่
        authorization_header = request.META['HTTP_AUTHORIZATION']
        if not authorization_header.startswith('Bearer '):
            return JsonResponse({'error': 'Invalid Access Token format'}, status=401)

        # ตรวจสอบการตรวจสอบ Access Token อื่นๆ ตามที่คุณต้องการ

        return self.get_response(request)
