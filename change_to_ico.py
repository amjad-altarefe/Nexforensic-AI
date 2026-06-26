from PIL import Image
from pathlib import Path

src = Path("C:\\Users\\amjad\\Desktop\\nexforensic\\nexforensic_ai_icon.png")
out = Path("C:\\Users\\amjad\\Desktop\\nexforensic\\nexforensic_ai_icon.ico")

img = Image.open(src).convert("RGBA")

# Make it square and save as multi-resolution Windows ICO
sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
img.save(out, format="ICO", sizes=sizes)

out
