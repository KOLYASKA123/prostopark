from django.urls import path
from django.views.generic import TemplateView
from .views import ProfileView, UserRegisterView, UserLoginView, user_logout, EmailVerify, ForgotPasswordView, MyPasswordResetView, home

urlpatterns = [
    path('', home, name='home'),
    path('list/', list, name='list'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('register/', UserRegisterView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('logout/', user_logout, name='logout'),
    path(
        'confirm_email/', 
        TemplateView.as_view(
            template_name='confirm_action.html',
            extra_context={
                'what_you_should_to_do_message': 'На указанную вами почту должно прийти письмо с ссылкой для верификации учётной записи. Перейдите по ней, чтобы продолжить работу.'
                }),
        name='confirm_email'
        ),
    path('verify_email/<uidb64>/<token>', EmailVerify.as_view(), name='verify_email'),
    path('invalid_verify/', TemplateView.as_view(template_name='invalid_verify.html'), name='invalid_verify'),
    path('forgot_password/', ForgotPasswordView.as_view(), name='forgot_password'),
    path(
        'password_reset/',
        TemplateView.as_view(
            template_name='confirm_action.html',
            extra_context={
                'what_you_should_to_do_message': 'На указанную вами почту должно прийти письмо с ссылкой для изменения пароля. Перейдите по ней, чтобы завершить смену пароля.'
                }),
        name='password_reset'
        ),
    path('password_reset_confirm/<uidb64>/<token>', MyPasswordResetView.as_view(), name='password_reset_confirm'),
    path('list/rokosi/', TemplateView.as_view(template_name='clearpage.html', extra_context={'src': 'www.youtube.com/embed/live_stream?channel=UCBa3dLmI6M-lWgOSWpeYHew&autoplay=1'}), name='rokosi'),
    path('list/baikova/', TemplateView.as_view(template_name='clearpage.html', extra_context={'src': 'www.youtube.com/embed/live_stream?channel=UCBa3dLmI6M-lWgOSWpeYHew&autoplay=1'}), name='baikova'),
    path('list/zapadnaya/', TemplateView.as_view(template_name='clearpage.html', extra_context={'src': 'www.youtube.com/embed/live_stream?channel=UCBa3dLmI6M-lWgOSWpeYHew&autoplay=1'}), name='zapadnaya'),
    path('list/error/', TemplateView.as_view(template_name='ooops.html'), name='ooops')
]
