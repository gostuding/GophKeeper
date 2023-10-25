# GophKeeper
Менеджер паролей 

## Компиляция серверной части проекта

Для компиляции серверной части проекта выполните команду:

```
go build -ldflags "-s -w -X 'main.version=VERSION' -X 'main.date=$(date +'%Y/%m/%d %H:%M:%S')'  -X 'main.commit=COMMENT'" cmd/server/main.go 
```
Где ```VERSION``` -  версия сборки, а ```COMMENT``` - коментарий для сборки.
При запуске серверной части проекта будут выведены версия, дата и коментарий пользователя.
В качестве примера, строка сборки может выглядеть так: 

```
go build -ldflags "-s -w -X 'main.version=v1.0.01' -X 'main.date=$(date +'%Y/%m/%d %H:%M:%S')'  -X 'main.commit=SERVER'" cmd/server/main.go
```
При завуске скомпилированного исполняемого файла будет выведена информация о сборке:
```
Build version: v1.0.01
Build date: 2023/09/03 22:00:46
Build commit: SERVER
```
Если параметры не указаны, то вывод будет следующим:
```
Build version: N/A
Build date: N/A
Build commit: N/A
```

## Компиляция агента проекта

Параметры аналогичны выше описанным, за исключением пути до main.go файла. Пример команды:
```
go build -ldflags "-X 'main.version=v1.0.01' -X 'main.date=$(date +'%Y/%m/%d %H:%M:%S')'  -X 'main.commit=AGENT'" cmd/agent/main.go
```
