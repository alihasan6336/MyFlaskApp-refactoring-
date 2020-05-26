import datetime

now = datetime.datetime.now()
dt_string = now.strftime("%Y-%m-%d %H:%M:%S")

print(type(now), type(dt_string))