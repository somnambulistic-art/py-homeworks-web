import asyncio
import email
import aiosqlite
import aiosmtplib

SENDER_USERNAME = "test@test.com"
SENDER_PASSWORD = "test123"


class User:
    def __init__(self, id, username: str, email: str, password: str):
        self.id = id
        self.username = username
        self.email = email
        self.password = password


async def create_coroutines():
    async with aiosqlite.connect('db.sqlite') as db:
        async with db.execute("SELECT * FROM user") as cursor:
            users = [User(*user) for user in await cursor.fetchall()]
    return [create_and_send_message(user) for user in users]


async def create_and_send_message(user, sender_username=SENDER_USERNAME, sender_password=SENDER_PASSWORD):
    message = email.message.EmailMessage()
    message["From"] = "Flask app"
    message["To"] = user.email
    message["Subject"] = 'Очень благодарственное письмо'
    message.set_content(f'Уважаемый {user.username}!\n Спасибо, что пользуетесь нашим сервисом объявлений.')
    await aiosmtplib.send(message, username=sender_username, password=sender_password,
                          hostname="smtp.gmail.com", port=465, use_tls=True)


async def main():
    tasks = await create_coroutines()
    for task in tasks:
        await task


if __name__ == '__main__':
    event_loop = asyncio.get_event_loop()
    event_loop.run_until_complete(main())
