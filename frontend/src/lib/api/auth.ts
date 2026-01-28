import { authConfig, apiConfig } from './config';
import { handleResponse } from './client';
import { LoginParams, LoginResponse, User } from '@/types/crm';

export async function login(params: LoginParams): Promise<LoginResponse> {

  const body = new URLSearchParams();
  body.append('username', params.username);
  body.append('password', params.password);
  const endpoint = '/api/auth/token'; 

  const response = await fetch(`${authConfig.baseURL}${endpoint}`, {
    method: 'POST',
    headers: authConfig.headers, 
    body: body.toString(),  
  });

  return handleResponse<LoginResponse>(response);  
} 

export async function getCurrentUser(token: string): Promise<User>{ 
    
  const endpoint = '/api/auth/me'; 

  const response = await fetch(`${apiConfig.baseURL}${endpoint}`, { 
    method: 'GET',  
    headers: {
      'Authorization': `Bearer ${token}`, 
      'Content-Type': 'application/json',
    },
  });

  const data = await handleResponse<any>(response); 

    return {
        id: data.id,
        fullName: data.full_name,
        email: data.email,
        isActive: data.is_active,
        createdAt: new Date(data.created_at),
        updatedAt: new Date(data.updated_at),
    };
}

export async function logout(): Promise<void> {
  localStorage.removeItem('token');
}