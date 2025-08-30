import os
from PIL import Image
import shutil

# 获取文件夹路径
base_dir = os.getcwd()
storage_dir = os.path.join(base_dir, "images", "Storage")
portfolio_modals_dir = os.path.join(base_dir, "images", "portfolio", "modals")
portfolio_dir = os.path.join(base_dir, "images", "portfolio")

# 确保目标文件夹存在
os.makedirs(portfolio_modals_dir, exist_ok=True)
os.makedirs(portfolio_dir, exist_ok=True)

# 获取 Storage 文件夹中的所有图片文件（包括 .jpg）
image_files = [f for f in os.listdir(storage_dir) if f.lower().endswith(('jpeg', 'png', 'gif', 'bmp', 'jpg'))]

for idx, image_file in enumerate(image_files):
    # 完整的文件路径
    image_path = os.path.join(storage_dir, image_file)
    
    try:
        with Image.open(image_path) as img:
            # 如果文件不是 JPG 格式，将其转换为 JPG 格式
            if img.format != 'JPEG':
                img = img.convert("RGB")
                output_path = os.path.join(storage_dir, f"converted_{idx}.jpg")
                img.save(output_path, "JPEG")
            else:
                output_path = image_path  # 如果是 JPG 文件，就直接使用原文件路径
            
            # 按照顺序重命名为 modals 中的文件名
            new_name = f"psc ({idx+1}).jpg"
            new_path = os.path.join(portfolio_modals_dir, new_name)
            
            # 重命名并复制到 modals 文件夹
            shutil.copy(output_path, new_path)
            
            # 将 modals 中的图片裁切为正方形并保存到 portfolio
            with Image.open(new_path) as img_to_crop:
                width, height = img_to_crop.size
                new_size = min(width, height)
                left = (width - new_size) / 2
                top = (height - new_size) / 2
                right = (width + new_size) / 2
                bottom = (height + new_size) / 2
                
                img_to_crop = img_to_crop.crop((left, top, right, bottom))
                
                # 保存裁切后的图片到 portfolio 文件夹
                final_name = f"psc ({idx+1}).jpg"
                final_path = os.path.join(portfolio_dir, final_name)
                img_to_crop.save(final_path)
                
            # 删除临时转换的图片（如果有）
            if output_path != image_path:
                os.remove(output_path)
    
    except Exception as e:
        print(f"处理文件 {image_file} 时发生错误: {e}")

print("操作完成！")
