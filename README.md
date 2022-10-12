# StudySpringJwt

Spring security + JWT例子。

## 说明

1. 采用jjwt 0.9.1生成token
2. 客户端请求http://localhost:8080/authenticate来申请token
3. 在访问http://localhost:8080/user时，需要在请求头添加：
```java
{
    "Authorization": "Bearer <token>"
}