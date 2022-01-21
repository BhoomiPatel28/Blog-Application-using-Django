from django.shortcuts import render, redirect
from django.urls import reverse_lazy
from django.contrib.auth.decorators import login_required, user_passes_test
from django.utils.decorators import method_decorator
from django.contrib.auth.models import User
from django.views.generic import CreateView, UpdateView
from django.contrib import messages
from .models import Post, Comment, Category
from django.contrib.auth import authenticate, login, logout
from django.urls import reverse_lazy
from django.shortcuts import redirect, render
from django.contrib.auth import logout
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from .tokens import generate_token
from django.core.mail import EmailMessage, send_mail
from blogproject import settings
from django.db.models import Q
from django.contrib import messages
import re


def MainView(request):
    posts = Post.objects.filter(visible=True)
    categories = Category.objects.all()
    category = ''
    if request.method == 'GET':
        if 'category' in request.GET:
            category = request.GET['category']
            if category != 'All':
                posts = Post.objects.filter(category__name=category, visible=True)
    ctx = {'posts' : posts.order_by('-post_date'), 'category' : category, 'categories' : categories}
    return render(request, 'blogapp/mainview.html', ctx)

def PostDetailView(request, pk):
    post = Post.objects.get(pk=pk)
    if post.visible == True or request.user.is_superuser or post.author == request.user:
        if request.method == 'POST':
            name = request.POST.get('name')
            comment = request.POST.get('comment')
            comment = Comment(body=comment, author=name, post=post, visible=False)
            comment.save()
            messages.info(request, 'Thank you for your comment. It is sent for review and will appear under the post very soon.')
        comments = Comment.objects.filter(post=post, visible=True)
        ctx = {'post': post, 'comments' : comments}
        return render(request, 'blogapp/postview.html', ctx)
    else:
        return redirect('compapp:NoAccess')

def LikePost(request, pk):
    post = Post.objects.get(pk=pk)
    post.likes = post.likes + 1
    post.save()
    messages.info(request, 'I\'m glad you liked the article. Thank you for reading!')
    return redirect('blog:PostDetailView', pk)

@method_decorator(login_required(), 'dispatch')
class PostCreateView(CreateView):
    model = Post
    fields = ['title', 'body', 'snippet', 'category']
    success_url = reverse_lazy('blog:MainView')
    def form_valid(self, form):
        object = form.save(commit=False)
        object.author = self.request.user
        object.save()
        post = Post.objects.get(pk=object.pk)
        messages.info(self.request, 'Your post is saved and sent for review. Once it is approved, it will be published.')
        return super(PostCreateView, self).form_valid(form)

@method_decorator(login_required(), 'dispatch')
class PostEditView(UpdateView):
    model = Post
    fields = ['title', 'body', 'snippet', 'category']
    success_url = reverse_lazy('blog:MainView')
    def get_queryset(self):
        qs = super(PostEditView, self).get_queryset()
        if self.request.user.is_superuser:
            return qs
        else:
            return qs.filter(author=self.request.user, locked=False)

@login_required()
def MyArticlesView(request):
    posts = Post.objects.filter(author=request.user)
    categories = []
    for post in posts:
        if not post.category in categories:
            categories.append(post.category)
    category = ''
    if request.method == 'GET':
        if 'category' in request.GET:
            category = request.GET['category']
            if category != 'All':
                posts = posts.filter(category__name=category)
    ctx = {'posts' : posts.order_by('-post_date'), 'category' : category, 'categories' : categories, 
        'view' : 'MyArticlesView'}
    return render(request, 'blogapp/mainview.html', ctx)

def LoginView(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('blog:MainView')
        else:
            messages.error(request, "Bad Credentials!!")
            return render(request,"login.html")

    return render(request,"login.html")


def Register(request):
    if request.method == 'POST':
        username = request.POST['username']
        fname = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        password = request.POST['password']
        cpassword = request.POST['cpassword']
        

        if User.objects.filter(username=username):
            messages.error(request, 'Username is already Exist!')
            return render(request, 'register.html', {'err':True})

        if User.objects.filter(Q(email=email)):
            messages.error(request, 'Email is already Exist!')
            return render(request, 'register.html', { 'err':True })

        if len(password) < 8 or (not re.search('[a-z]', password)) or (not re.search('[A-Z]', password)) or (not re.search('[0-9]', password)) or (not re.search('[_#@!$%&]',password)):
            messages.error(request, 'The password must be 8 charater long with the at least one small and captial latters, number and special characters')
            return render(request, 'register.html',{'err': True})
        
        if password!=cpassword:
            messages.error(request, 'Password does not match')
            return render(request, 'register.html',{'err': True})

        newUser = User.objects.create_user(username,email,password)
        newUser.first_name = fname
        newUser.last_name = lname
        newUser.is_active = False
        newUser.save()

        current_site = get_current_site(request)
        email_subject = "Confirm your email @Blog Application!"
        email_message = render_to_string('email_confirmation.html',{
                'name': username,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(newUser.pk)),
                'token': generate_token.make_token(newUser)
        })

        email_send = EmailMessage(
                email_subject,
                email_message,
                settings.EMAIL_HOST_USER,
                [newUser.email]
            )
        email_send.fail_silently = True
        email_send.send()
        messages.success(request, 'Your account is successfully created!! Please check your email to confirm your email address in order to activate your account.')
        return redirect('/login')

    return render(request, 'register.html')

def LogoutView(request):
    messages.success(request, 'Successfully logged out...')
    logout(request)
    return redirect('blog:MainView')

def activate(request,uidb64,token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        new_user = User.objects.get(pk=uid)
    except (TypeError,ValueError,OverflowError, User.DoesNotExist):
        new_user = None

    if new_user is not None and generate_token.check_token(new_user,token):
        new_user.is_active = True
        new_user.save()
        messages.success(request, 'Your account is successfully activated. Kindly login with your credentials!')
        return redirect('/login')