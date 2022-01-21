from django.urls import path
from . import views

app_name = 'blog'

urlpatterns = [
    path('', views.MainView, name='MainView'),
    path('post/<int:pk>', views.PostDetailView, name='PostDetailView'),
    path('post/create', views.PostCreateView.as_view(), name='PostCreateView'),
    path('post/<int:pk>/edit', views.PostEditView.as_view(), name='PostEditView'),
    #path('post/<int:pk>/approve', views.ApprovePost, name='ApprovePost'),
    path('myposts/', views.MyArticlesView, name='MyArticlesView'),
    path('likepost/<int:pk>', views.LikePost, name='LikePost'),
    path('login/', views.LoginView, name='LoginView'),
    path('register/', views.Register, name='Register'),
    path('logout/', views.LogoutView, name='LogoutView'),
    path('activate/<uidb64>/<token>/', views.activate, name='activate'),
] 