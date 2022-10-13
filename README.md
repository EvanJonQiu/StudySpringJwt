# StudySpringJwt

Spring security + JWT例子。

## 说明 demo_2
1. Spring Security未来会将`WebSecurityConfigurerAdapter`废弃，希望用户转向基于组件的安全配置。
    \[参考：[Spring Security without the WebSecurityConfigurerAdapter](https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter) \]

2. jjwt采用jjwt-api 0.11.5

## 说明 demo_1

1. 采用jjwt 0.9.1生成token
2. 客户端请求http://localhost:8080/authenticate来申请token
3. 在访问http://localhost:8080/user时，需要在请求头添加：
```java
{
    "Authorization": "Bearer <token>"
}

