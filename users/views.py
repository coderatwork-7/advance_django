import requests
import logging
from django.urls import reverse
from rest_framework import viewsets, status, generics
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework.response import Response
from rest_framework.decorators import action
from django.contrib.auth import authenticate, login
from rest_framework.exceptions import NotFound, ValidationError
from django.shortcuts import render, redirect

from django.conf import settings
from .models import User, Question, Choice, Answer 
from .utils import validate_phone_number, send_verificaiton_email
from .serializers import UserSerializer, QuestionSerializer , AnswerSerializer, CustomUserSerializer
log =  logging.getLogger("main")
# User ViewSet for registration with answers
class UserViewSet(viewsets.ViewSet):
    def get_permissions(self):
        if self.action in ['create', 'login']:
            permission_classes = [AllowAny]
        else:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]

    # sign up - Handle user registration along with answering questions.
    def create(self, request):
        serializer = UserSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    # sign in - Handle user login and return JWT token.
    @action(detail=False, methods=['post'], permission_classes=[AllowAny])
    def login(self, request):
        email = request.data.get("email")
        password = request.data.get("password")
        user = authenticate(request, email=email, password=password)
        if user is not None:
            return Response({"message": "Login successful"}, status=status.HTTP_200_OK)
        else:
            return Response({"message": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)


    def list(self, request):
        """
        List all users (for authenticated users only).
        """
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

    def retrieve(self, request, pk=None):
        """
        Retrieve a single user by user ID.
        """
        try:
            user = User.objects.get(pk=pk)
            serializer = UserSerializer(user)
            return Response(serializer.data)
        except User.DoesNotExist:
            return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)


    def update(self, request, pk=None):
        """
        Update a user's information.
        """
        try:
            user = User.objects.get(pk=pk)
            serializer = UserSerializer(user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

    def destroy(self, request, pk=None):
        """
        Delete a user.
        """
        try:
            user = User.objects.get(pk=pk)
            user.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except User.DoesNotExist:
            return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)



class QuestionViewSet(viewsets.ViewSet):
    """
    A ViewSet for listing, retrieving, creating, updating, and deleting questions.
    """
    permission_classes = [IsAuthenticated]

    def list(self, request):
        """
        List all questions.
        """
        questions = Question.objects.all()
        serializer = QuestionSerializer(questions, many=True)
        return Response(serializer.data)

    def retrieve(self, request, pk=None):
        """
        Retrieve a single question by its ID.
        """
        try:
            question = Question.objects.get(pk=pk)
            serializer = QuestionSerializer(question)
            return Response(serializer.data)
        except Question.DoesNotExist:
            return Response({'detail': 'Question not found.'}, status=status.HTTP_404_NOT_FOUND)

    def create(self, request):
        """
        Create a new question along with its choices.
        """
        serializer = QuestionSerializer(data=request.data)
        if serializer.is_valid():
            question = serializer.save()
            
            # Create choices if provided
            choices_data = request.data.get('choices')
            if choices_data:
                for choice_data in choices_data:
                    Choice.objects.create(question=question, **choice_data)
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        """
        Update an existing question along with its choices.
        This method will replace the question and its choices entirely.
        """
        try:
            question = Question.objects.get(pk=pk)
        except Question.DoesNotExist:
            return Response({'detail': 'Question not found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = QuestionSerializer(question, data=request.data)
        if serializer.is_valid():
            question = serializer.save()

            # Delete old choices and create new ones
            question.choices.all().delete()
            choices_data = request.data.get('choices')
            if choices_data:
                for choice_data in choices_data:
                    Choice.objects.create(question=question, **choice_data)
            
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        """
        Partially update an existing question.
        Only the provided fields in the request body will be updated.
        """
        try:
            question = Question.objects.get(pk=pk)
        except Question.DoesNotExist:
            return Response({'detail': 'Question not found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = QuestionSerializer(question, data=request.data, partial=True)
        if serializer.is_valid():
            question = serializer.save()

            # If choices are provided in the partial update, replace them
            choices_data = request.data.get('choices')
            if choices_data is not None:
                question.choices.all().delete()
                for choice_data in choices_data:
                    Choice.objects.create(question=question, **choice_data)

            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        """
        Delete a question and its associated choices.
        """
        try:
            question = Question.objects.get(pk=pk)
            question.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Question.DoesNotExist:
            return Response({'detail': 'Question not found.'}, status=status.HTTP_404_NOT_FOUND)



class AnswerViewSet(viewsets.ViewSet):
    """
    A ViewSet for creating, reading, updating, and deleting answers for a user.
    """
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Return only answers belonging to the authenticated user.
        """
        return Answer.objects.filter(user=self.request.user)

    def list(self, request):
        """
        List all answers for the authenticated user.
        """
        queryset = self.get_queryset()
        serializer = AnswerSerializer(queryset, many=True)
        return Response(serializer.data)

    def create(self, request):
        """
        Create a new answer for the authenticated user.
        """
        serializer = AnswerSerializer(data=request.data, many=True)
        if serializer.is_valid():
            for answer_data in serializer.validated_data:
                question = answer_data['question']
                if question.question_type == Question.TEXT:
                    Answer.objects.create(user=request.user, question=question, text=answer_data['text'])
                else:
                    answer = Answer.objects.create(user=request.user, question=question)
                    answer.choices.set(answer_data['choices'])
                    answer.save()
            return Response({"status": "Answers created successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        """
        Retrieve a specific answer by ID for the authenticated user.
        """
        try:
            answer = self.get_queryset().get(pk=pk)
            serializer = AnswerSerializer(answer)
            return Response(serializer.data)
        except Answer.DoesNotExist:
            return Response({'detail': 'Answer not found.'}, status=status.HTTP_404_NOT_FOUND)

    def update(self, request, pk=None):
        """
        Update an existing answer for the authenticated user.
        """
        try:
            answer = self.get_queryset().get(pk=pk)
        except Answer.DoesNotExist:
            return Response({'detail': 'Answer not found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = AnswerSerializer(answer, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        """
        Delete an answer for the authenticated user.
        """
        try:
            answer = self.get_queryset().get(pk=pk)
            answer.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Answer.DoesNotExist:
            return Response({'detail': 'Answer not found.'}, status=status.HTTP_404_NOT_FOUND)

    @action(detail=False, methods=['delete'])
    def delete_all(self, request):
        """
        Delete all answers for the authenticated user.
        """
        count, _ = self.get_queryset().delete()
        return Response({'status': f'{count} answers deleted.'}, status=status.HTTP_204_NO_CONTENT)
    
class GoogleOAuth2Viewset(viewsets.ViewSet):

    permission_classes = [AllowAny]

    def create(self, request,  *args, **kwargs):

        try:
            code = request.data["code"]
        except Exception as e:
            return Response({'error': 'No code provided'}, status=status.HTTP_400_BAD_REQUEST)

        token_url = 'https://oauth2.googleapis.com/token'

        data = {
            'code': code,
            'client_id': settings.GOOGLE_CLIENT_ID,
            'client_secret': settings.GOOGLE_CLIENT_SECRET_KEY,
            'redirect_uri': 'http://localhost:8080/v1/api/core/google-callback',
            'grant_type': 'authorization_code'
        }
        try:
    
            response = requests.post(token_url, data=data)
            if not response.status_code == 200:
                return Response({"error": "Authentication code is invalid please try again.", "status": response.status_code}, status=status.HTTP_400_BAD_REQUEST)
            token_data = response.json()

            access_token = token_data.get('access_token')
            id_token = token_data.get('id_token')
            
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        try:
            userinfo_url = 'https://www.googleapis.com/oauth2/v3/userinfo/'
            headers = {'Authorization': f'Bearer {access_token}'}
            user_info_response = requests.get(userinfo_url, headers=headers)
            user_info = user_info_response.json()
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=user_info['email'])
            user.first_name= user_info["given_name"]
            user.last_name= user_info["family_name"]
            user.save()

        except Exception as e:
            user = None
            log.info('Failed to retrieve user information')

        try:
            if not user:
                user = User(email = user_info['email'])
                user.first_name= user_info["given_name"]
                user.last_name= user_info["family_name"]
                user.set_unusable_password()
                user.is_verified = True
                user.save()
        except Exception as e:
            log.error(f'Failed to create user ==> {e}')
            return Response({"error": "Could not create user,"}, status=status.HTTP_400_BAD_REQUEST) 
        
        backend = 'social_core.backends.google.GoogleOAuth2'

        user.backend = backend
        login(self.request, user, backend=backend)
        
        
        return Response({"access": str(AccessToken.for_user(user)), "refresh": str(RefreshToken.for_user(user))}, status=status.HTTP_200_OK)


class FacebookOAuth2Viewset(viewsets.ViewSet):
    
    permission_classes = [AllowAny]
    def create(self, request):

        try:
            code = request.data["code"]
        except Exception as e:
            return Response({'error': 'No code provided'}, status=status.HTTP_400_BAD_REQUEST)

        token_url = 'https://graph.facebook.com/v10.0/oauth/access_token'
        token_params = {
            'client_id': settings.SOCIAL_AUTH_FACEBOOK_KEY,
            'redirect_uri': "http://localhost:8080/v1/api/core/facebook-callback/",
            'client_secret': settings.SOCIAL_AUTH_FACEBOOK_SECRET,
            'code': code,
        }
        token_response = requests.get(token_url, params=token_params)
        token_data = token_response.json()
        if 'access_token' not in token_data:
            return Response({'error': 'Failed to fetch access token'}, status=400)

        access_token = token_data['access_token']

        user_info_url = 'https://graph.facebook.com/me'
        user_info_params = {
            'fields': 'id,name,email,picture,birthday,gender,location,hometown',
            'access_token': access_token,
        }
        user_info_response = requests.get(user_info_url, params=user_info_params)
        user_info = user_info_response.json()
        if 'email' not in user_info:
            return Response({'error': 'Failed to retrieve user information'}, status=400)
        try:
            user = User.objects.get(email=user_info['email'])
            user.first_name = user_info["name"].split()[0]
            user.last_name = user_info["name"].split()[-1]
            user.save()

        except Exception as e:
            user = None
            log.info('Failed to retrieve user information')
        try:
            if not user:
                user = User.objects.create(email = user_info['email'])
                user.first_name = user_info["name"].split()[0]
                user.last_name = user_info["name"].split()[-1]
                user.is_verified = True
                user.set_unusable_password()
                user.save()
        except Exception as e:
            log.error(f'Failed to create user ==> {e}')
            return Response({"error": "Could not create user,"}, status=status.HTTP_400_BAD_REQUEST)

        backend = 'social_core.backends.facebook.FacebookOAuth2'

        user.backend = backend
        login(self.request, user, backend=backend)

        # return Response({'message': 'User logged in successfully', 'user': user_info, "access": access_token}, status=200)
        return Response({"access": str(AccessToken.for_user(user)), "refresh": str(RefreshToken.for_user(user))}, status=status.HTTP_200_OK)
    
class FacebookCallBackViewset(viewsets.ViewSet):
    permission_classes = [AllowAny]

    def list(self, *args, **kwargs):
        print("=="*15 + ">" + self.request.GET.get("code"))
        return Response("Got it", status=status.HTTP_200_OK)
    
class GoogleCallBackViewset(viewsets.ViewSet):
    permission_classes = [AllowAny]

    def list(self, *args, **kwargs):
        print("="*15 + ">" + self.request.GET.get("code"))
        return Response("Got it", status=status.HTTP_200_OK)
    
class VerifyEmailView(viewsets.ViewSet):
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

    def get_absolute_url(self, *args, **kwargs):
        request = self.request
        schema = request.scheme
        host = request.get_host()

        return f"{schema}://{host}/"
    
    def list(self, request):
        token = request.GET.get('token')
        token = RefreshToken(token)
        try:
            user = User.objects.get(id = token.payload["user_id"])
            user.is_verified = True
            user.save()
            RefreshToken(str(token)).blacklist()    
            log.info(self.get_absolute_url())
            log.info("Link " + "="*50)
            link = self.get_absolute_url()
            return redirect(link)
        except Exception as e:
            log.error(str(e))
            raise ValidationError(f"Error on Payment Successful {e}")


class ForgetPasswordViewset(viewsets.ViewSet):

    permission_classes = [AllowAny,]
    LOCALHOSTS = ["127.0.0.1:8080"]

    def get_absolute_url(self, *args, **kwargs):
        request = self.request
        schema = request.scheme
        host = request.get_host()
        return f"{schema}://{host}/"

    def create(self, request, *args, **kwargs):
        email = request.data.get('email')
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            log.error(f'Error on Forget Password ==> {e}')
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        if not user.is_verified:
            return Response({'error': "Please verify your email first. You'r email is not verified"}, status=status.HTTP_400_BAD_REQUEST)

        token = RefreshToken.for_user(user)
        if request.META["HTTP_HOST"] in self.LOCALHOSTS:
            request.META['HTTP_HOST'] = "localhost:8080"
        else:
            request.META['HTTP_HOST'] = request.META["HTTP_HOST"]

        rev = reverse('reset_password-list')

        absolute_link = request.build_absolute_uri(rev)
        absolute_url = absolute_link+"?token="+str(token)
        reset_url = self.get_absolute_url() + "v1/api/core/reset-password/" + str(token)
        send_verificaiton_email(
            'Reset Password',
            user,
            f'Click on the link below to reset your password: {reset_url}',)
        return Response({"success": "An Email has been sent to reset your password"}, status=status.HTTP_200_OK)
    
class ResetPasswordViewset(viewsets.ViewSet):
    permission_classes = [AllowAny,]
    def create(self, request, *args, **kwargs):
        token = request.query_params.get('token')
        data = request.data
        try:
            refresh_token = RefreshToken(str(token))
            log.info(refresh_token)
            RefreshToken(str(token)).blacklist()    

            user_id = refresh_token['user_id']
            user = User.objects.get(id=user_id)
        except Exception as e:
            log.error(f'Error on Reset Password ==> {e}')
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            if data["password"] == data["confirm_password"]:
                user.set_password(data["password"])
                user.save()
                return Response({"success": "Password has been reset successfully"}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            log.error(f'Error on Reset Password ==> {e}')
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
class LoginViewset(generics.GenericAPIView):
    serializer_class = CustomUserSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        data = request.data
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return Response({"error": "Email and password are required."},
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_404_NOT_FOUND)

        if user.check_password(password):
            validated_serializer = CustomUserSerializer(user)
            return Response(validated_serializer.data, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid password"}, status=status.HTTP_401_UNAUTHORIZED)
