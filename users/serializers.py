import logging
from django.http import HttpRequest
from django.conf import settings
from django.utils import timezone
from django.urls import reverse
from datetime import timedelta
from rest_framework import serializers
from django.contrib.auth import authenticate
from rest_framework.reverse import reverse_lazy
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.renderers import BrowsableAPIRenderer, JSONRenderer, HTMLFormRenderer
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenVerifySerializer
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from .utils import validate_phone_number, send_verificaiton_email
from .models import User, Question, Choice, Answer

log = logging.getLogger("main")

class ChoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Choice
        fields = ('id', 'text')

class QuestionSerializer(serializers.ModelSerializer):
    choices = ChoiceSerializer(many=True, read_only=True)

    class Meta:
        model = Question
        fields = ('id', 'title', 'question_type', 'choices')

class AnswerSerializer(serializers.ModelSerializer):
    choices = serializers.PrimaryKeyRelatedField(many=True, queryset=Choice.objects.all(), required=False)

    class Meta:
        model = Answer
        fields = ('question', 'choices', 'text')

    def validate(self, data):
        question = data['question']
        if question.question_type == Question.SINGLE_CHOICE:
            if len(data.get('choices', [])) != 1:
                raise serializers.ValidationError("Must select exactly one choice for single choice questions.")
        elif question.question_type == Question.MULTIPLE_CHOICE:
            if len(data.get('choices', [])) < 1:
                raise serializers.ValidationError("Must select at least one choice for multiple choice questions.")
        elif question.question_type == Question.TEXT:
            if not data.get('text'):
                raise serializers.ValidationError("Text field is required for free text questions.")
        return data


class UserSerializer(serializers.ModelSerializer):
    LOCALHOSTS = ["127.0.0.1:8080"]

    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    # nested AnswerSerializer to handle answers during user registration
    answers = AnswerSerializer(many=True)   

    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'phone', 'password', 'answers')

    def generate_validation_link(self, user):
        token = RefreshToken.for_user(user)
        request = self.context["request"]
        if request.META["HTTP_HOST"] in self.LOCALHOSTS:
            request.META['HTTP_HOST'] = "localhost:8080"
        else:
            request.META['HTTP_HOST'] = request.META["HTTP_HOST"]

        rev = reverse('verify-list')

        absolute_link = request.build_absolute_uri(rev)
        absolute_url = absolute_link+"?token="+str(token)

        # Send verification email
        subject = "Email Verification"
        message = f"Hi {user.first_name}, please verify your email by clicking the link:  {absolute_url}"
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [user.email]
        try:
            
            user.save()
            log.info(absolute_url)
            send_verificaiton_email(
                "Verification Email",
                user,
                f"Please click on the link to verify your email. \n {absolute_url}")
            return user
        except Exception as e:
            user.delete()
            log.error(f"Can't create User {e}")
            raise ValueError(f"Can't create User {e}")
        
    def create(self, validated_data):
        answers_data = validated_data.pop('answers')
        
        user = User(
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            phone=validated_data['phone']   )
        user.set_password(validated_data['password'])
        user.save()

        return user

    def validate_phone(self, value):
        if not value.startswith('+'):
            raise serializers.ValidationError("Phone number must include the country code, starting with '+'.")
        if len(value) < 10 or len(value) > 15:
            raise serializers.ValidationError("Enter a valid phone number with the country code.")
        return value

    def validate_answers(self, value):
        for answer in value:
            question = answer['question']
            if question.question_type == Question.SINGLE_CHOICE:
                if len(answer.get('choices', [])) != 1:
                    raise serializers.ValidationError(f"Question (Single choice) '{question.title}' requires exactly one choice.")
            elif question.question_type == Question.MULTIPLE_CHOICE:
                if len(answer.get('choices', [])) < 1:
                    raise serializers.ValidationError(f"Question (Multiple choices) '{question.title}' requires at least one choice.")
            elif question.question_type == Question.TEXT:
                if not answer.get('text'):
                    raise serializers.ValidationError(f"Question (Free text) '{question.title}' requires text input.")
        return value

    def validate(self, data):
        self.validate_answers(data['answers'])
        return data


class CustomJWTSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        email = attrs.get("email")  # Get the email from the input data
        password = attrs.get("password")

        # Authenticate user using email and password
        user = authenticate(request=self.context["request"], email=email, password=password)

        
        if user is None:
            raise AuthenticationFailed({"error":"No such user"})

        if not user.is_verified:
            raise AuthenticationFailed({"error":"Please verify your email address to proceed"})
            

        refresh = self.get_token(user)
        data = super().validate(attrs)
        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)

        return {
            "user": UserSerializer(self.user).data,
            "refresh": str(data['refresh']),
            "access": str(data['access'])
        }



""" 
POST /api/users/
{
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "phone": "+1234567890",
    "password": "password123",
    "answers": [
        {
            "question": 1,
            "choices": [1],  // Only for single/multiple choice questions
            "text": ""       // Only for text-based questions
        },
        {
            "question": 2,
            "choices": [3, 4], // Multiple choices
            "text": ""         // Leave empty for non-text questions
        },
        {
            "question": 3,
            "choices": [],
            "text": "My main objective is long-term investment."  // For text-based questions
        }
    ]
}


"""


class CustomUserSerializer(serializers.ModelSerializer):

    access_token = serializers.SerializerMethodField(read_only=True)
    refresh_token = serializers.SerializerMethodField(read_only=True)
    def get_access_token(self, obj):

        token = AccessToken.for_user(obj)
        token.set_exp(lifetime=timedelta(hours=5))  # Set to 5 hours

        return str(token)
    
    def get_refresh_token(self, obj):
        return str(RefreshToken.for_user(obj))
    
    class Meta:
        model = User
        fields = ('id',
                'email', 
                'first_name', 
                'last_name',
                "access_token",
                "refresh_token"
                )