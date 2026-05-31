from dotenv import load_dotenv

from chatloop_v3 import ModelRouter


load_dotenv()

router = ModelRouter.from_env()
reply, profile = router.call(
    messages=[{"role": "user", "content": "Reply with one short sentence: ARISE is online."}],
    temperature=0.1,
    task="fast",
)

print(f"Route: {profile.label}")
print(reply)
