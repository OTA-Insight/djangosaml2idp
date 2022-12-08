# Após rodar o Docker Compose

- Rodar o seguinte comando em outro terminal:

    `docker exec -it djangosaml2idp-idp python manage.py loaddata ../dump.json`

Isso roda a fixture adicionando o usuário Teste e adicionando o SP(de acordo com os links que estão rodando no código).

```
Username: teste
Senha: 123123
```

PS: Caso queira trocar os endpoints no código, não esqueça de mudar o SP na Base/Admin.