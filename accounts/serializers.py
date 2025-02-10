from rest_framework import serializers
from .models import UserAccount

class RegistrationSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = UserAccount
        fields = ['username', 'first_name', 'last_name', 'email', 'phone','password', 'confirm_password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate(self, data):
        if data['password'] != data.pop('confirm_password'):
            raise serializers.ValidationError("Passwords do not match")
        return data

    def create(self, validated_data):
        validated_data['is_active'] = False 
        password = validated_data.pop('password')
        user = UserAccount.objects.create(**validated_data)  
        user.set_password(password)  
        user.save() 
        return user

class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)
    
 
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserAccount
        fields = ['id', 'username', 'first_name','last_name','email', 'image' ,'created_at', 'phone']    
        

class PasswordChangeSerializer(serializers.Serializer):
    user= serializers.CharField(required=True)
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)





