# Windows Inventory Lite

> Проект сделан под личные потребности автора. Идея и контроль - автора. Реализация - ИИ Claude (Anthropic).

![Windows Inventory Lite](./docs/images/logo.png)

[![Release](https://img.shields.io/github/v/release/didimozg/windows-inventory-lite?display_name=tag)](https://github.com/didimozg/windows-inventory-lite/releases)
[![CI](https://github.com/didimozg/windows-inventory-lite/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/didimozg/windows-inventory-lite/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/didimozg/windows-inventory-lite)](./LICENSE)

## Описание

Windows Inventory Lite - легкий инструмент инвентаризации для небольших сетей на Windows и Linux, где полноценная система управления активами избыточна. Собирает данные об установленном ПО, аппаратных характеристиках, версии ОС и статусе активации Office на рабочих станциях, серверах Windows и хостах Debian/Ubuntu - всё через один web-дашборд.

Клиент и сервер для Windows - небольшие самодостаточные службы на C# с целевой платформой .NET Framework 3.5, без IIS, SQL Server, Python, Node.js и NuGet-пакетов. Linux-клиент - один статический бинарник на Go, отчитывающийся по HTTPS. Windows-клиенты разворачиваются через WinRM прямо из дашборда или через сценарий запуска компьютера в GPO; Linux-клиенты - по SSH из того же дашборда.

## Что умеет

- Собирает версию ОС, аппаратные данные (CPU, ОЗУ, накопители, USB-детект), список установленного ПО и статус активации Windows/Office с каждой отчитывающейся машины - и с Windows, и с Linux.
- Один дашборд показывает оба парка вместе: объединённая таблица Clients (с фильтром All/Windows/Linux), общий раздел Hardware и общие сводные плитки - плюс таблица Software и отдельная таблица Services для Linux.
- Устанавливает, обновляет и удаляет Windows-клиент через WinRM, а Linux-клиент - по SSH (ключ или пароль), прямо из дашборда, без захода на каждую машину вручную.
- Опциональное развёртывание через GPO для парков Windows, где предпочитают сценарий запуска компьютера, а не push через WinRM.
- Каталог лицензий на ПО, который ведётся вручную и привязывается к конкретным компьютерам.
- Опциональные HTTPS (сертификаты хранятся в собственном хранилище сервера, обратный прокси не нужен), Basic Auth, синхронизация описания компьютеров с Active Directory, импорт списка компьютеров из AD и токен приёма отчётов.

Полный список параметров всех скриптов и ключей конфигурации - в [справочнике параметров](./docs/parameters-reference.md); что аутентифицируется, что шифруется при хранении и что проверить перед тем, как выставить сервер за пределы доверенной сети - в [модели угроз](./docs/threat-model.md).

## Требования

**Windows-клиент:** Windows 7/8/10/11, .NET Framework 3.5+, встроенный PowerShell.
**Windows-сервер:** Windows Server или настольная Windows, .NET Framework 3.5+, один TCP-порт под HTTP и опционально второй под HTTPS (по умолчанию 8080/8443).
**Linux-клиент:** Debian или Ubuntu, amd64.
**Машина сборки:** Windows с компилятором C# из .NET Framework и PowerShell 5.1+; Go нужен только для пересборки Linux-клиента из исходников (иначе в репозитории уже лежит готовый бинарник).

## Быстрый старт

Собрать и установить сервер:

```powershell
.\src\Build-Server.ps1
.\src\Install-Server.ps1 -ListenPrefix 'http://+:8080/' -OpenFirewall
```

Открыть дашборд по адресу `http://<сервер>:8080/`, а дальше либо запустить интерактивный мастер с пошаговым меню для любого сценария установки/удаления:

```powershell
.\src\Install-Wizard.ps1
```

либо установить один Windows-клиент напрямую:

```powershell
.\src\Install-Client.ps1 -ServerUrl 'http://<сервер>:8080/api/v1/inventory' -IntervalHours 6
```

либо развернуть Linux-клиент по SSH:

```powershell
.\src\Install-ClientDebianSSH.ps1 -ComputerName 192.0.2.10 -ServerUrl 'https://<сервер>/api/v1/linux/inventory' -CredentialUsername root -KeyPath C:\path\to\id_ed25519
```

Полный список параметров каждого скрипта, все ключи `server-config.json`, развёртывание через GPO и push через WinRM - в [docs/parameters-reference.md](./docs/parameters-reference.md).

## Работа с дашбордом

Дашборд - однастраничное приложение с горизонтальной панелью сверху: **Dashboard** (сводные плитки и графики по ОС и оборудованию для обоих парков), **Fleet** (выпадающий список: Clients, Software, Services, Hardware, Licenses - Clients и Hardware объединяют обе платформы за фильтром All/Windows/Linux), **Install** (вкладки Actions, Updates, Package - установка и удаление по WinRM/SSH с режимом автоопределения, обновление устаревших клиентов, скачивание автономного пакета установки), **Settings** (Server, Windows, Linux, Certificate, Admin password) и **Logging** (журнал отклонённых попыток с неверным ingestion-токеном). Вход теперь идёт через отдельную страницу логина и настоящую серверную сессию, а не через нативный диалог Basic Auth браузера - сам Basic Auth (`curl -u user:pass`) по-прежнему работает без изменений для скриптов и автоматизации.

Дашборд опрашивает сервер каждые 30 секунд и обновляется на месте - сортировка, поиск и раскрытые строки не сбрасываются. Каждая таблица поддерживает сортировку по столбцам, поиск и экспорт в CSV (разделитель «;», UTF-8 BOM, открывается в Excel без танцев с кодировкой). Клик по компьютеру, названию ПО или группе оборудования раскрывает строку с деталями.

## Скриншоты

Сделаны на тестовом экземпляре с вымышленными данными - реальных хостов, учётных данных и лицензионных ключей здесь нет.

![Обзор дашборда](./docs/screenshots/dashboard-overview.png)

![Клиенты](./docs/screenshots/clients.png)

![Объединённый раздел Hardware](./docs/screenshots/hardware-view.png)

![Лицензии](./docs/screenshots/licenses.png)

## Документация

- [Справочник параметров и конфигурации](./docs/parameters-reference.md) - все параметры скриптов, ключи `server-config.json` и команды удаления.
- [Справочник HTTP API](./docs/api-reference.md) - все эндпоинты сервера.
- [Модель угроз](./docs/threat-model.md) - активы, границы доверия, обязательные инварианты, известные риски, меры защиты и заметки по эксплуатации.
- [CHANGELOG.md](./CHANGELOG.md) - полная история версий.

## Лицензия

[MIT License](./LICENSE). Copyright (c) 2026 didimozg.

## Благодарности

Реализовано с помощью [Claude Code](https://claude.com/claude-code) (Anthropic), с использованием следующих сторонних наборов агентов и скилов в процессе разработки:

- [obra/superpowers](https://github.com/obra/superpowers) - проработка идеи, планирование, subagent-driven development, систематическая отладка и процесс код-ревью.
- [affaan-m/ECC](https://github.com/affaan-m/ECC) - паттерны API design, frontend design и verification-loop.
- [anthropics/skills](https://github.com/anthropics/skills) - тестирование web-приложений через браузер.
