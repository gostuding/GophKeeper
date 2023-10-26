# GophKeeper
Менеджер паролей 

# Клонирование репозитория
```
git clone https://github.com/gostuding/GophKeeper
```
# Перед запуском сервера проверить наличие

1. СУБД postgres (см. документацию `https://postgrespro.ru/docs/postgresql/15/tutorial-install`)
2. База данный для сервера (по умолчанию используется название БД `gokeeper`) (см. документацию `https://postgrespro.ru/docs/postgresql/15/tutorial-createdb`)
3. Пользователь для работы с БД (по умолчанию используется `gopher`, пароль `password`) (см. документацию `https://postgrespro.ru/docs/postgresql/15/app-createuser`)
4. Параметры запуска прописываются в соответствующих файлах настройки клиента и сервера.

# Swager

1. Запустить сервер 
2. Открыть браузер по адресу: `http://$ADDRESS/swagger/` где `$ADDRESS` - адрес и порт сервера (default "localhost:8080")


## Запуск тестов golangci-lint

Установите локально golangci-lint (см. официальную документацию)
В директории проекта выполните команду:
```
./golint_run.sh
```
Реузльтаты работы golangci-lint будут отображены в файле `./golangci-lint/report.json`

## Запуск юнит-тестов 

В пакете internal/serve/storage хранятся тесты для функций работы с БД.
При выполнении команды ```go test ./...``` будут запущены тесты за исключением БД.
```
go test ./...
```
Для включения тестов к БД необходимо указать ```--tags=sql_storage```, 
а также строку подключения к БД: ```-args dsn="connection"```.
Пример запуска:
```
go test ./... --tags=sql_storage -args dsn="host=localhost user=postgres database=gokeeper"
``` 

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
