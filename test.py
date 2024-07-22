# Python code for Multiple Color Detection

import numpy as np
import cv2

# Capturing video through webcam
webcam = cv2.VideoCapture(0)

# Define color ranges and masks
color_ranges = {
    "Red": ([136, 87, 111], [180, 255, 255], (0, 0, 255)),
    "Green": ([25, 52, 72], [102, 255, 255], (0, 255, 0)),
    "Blue": ([94, 80, 2], [120, 255, 255], (255, 0, 0)),
    "Yellow": ([22, 93, 0], [45, 255, 255], (0, 255, 255)),
    "Orange": ([10, 100, 20], [25, 255, 255], (0, 165, 255)),
    "Purple": ([125, 50, 50], [150, 255, 255], (128, 0, 128)),
    "White": ([0, 0, 168], [172, 111, 255], (255, 255, 255)),
    "Black": ([0, 0, 0], [180, 255, 30], (0, 0, 0)),
}

# List of colors for cycling through them
colors = list(color_ranges.keys())
current_color_index = 0

# Start a while loop
while True:
    
    # Reading the video from the webcam in image frames
    _, imageFrame = webcam.read()
    
    # Convert the imageFrame in BGR (RGB color space) to HSV (hue-saturation-value) color space
    hsvFrame = cv2.cvtColor(imageFrame, cv2.COLOR_BGR2HSV)
    
    # Get the current color details
    current_color_name = colors[current_color_index]
    lower, upper, color = color_ranges[current_color_name]
    lower_np = np.array(lower, np.uint8)
    upper_np = np.array(upper, np.uint8)
    mask = cv2.inRange(hsvFrame, lower_np, upper_np)
    
    # Morphological Transform, Dilation
    kernel = np.ones((5, 5), "uint8")
    mask = cv2.dilate(mask, kernel)
    res = cv2.bitwise_and(imageFrame, imageFrame, mask=mask)
    
    # Creating contour to track the color
    contours, hierarchy = cv2.findContours(mask, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)
    
    for pic, contour in enumerate(contours):
        area = cv2.contourArea(contour)
        if area > 300:
            x, y, w, h = cv2.boundingRect(contour)
            imageFrame = cv2.rectangle(imageFrame, (x, y), (x + w, y + h), color, 2)
            cv2.putText(imageFrame, f"{current_color_name} Colour", (x, y), cv2.FONT_HERSHEY_SIMPLEX, 1.0, color)
    
    # Program Termination
    cv2.imshow("Color Detection in Real-Time", imageFrame)
    
    key = cv2.waitKey(10) & 0xFF
    if key == ord('q'):
        break
    elif key == ord('n'):
        current_color_index = (current_color_index + 1) % len(colors)

webcam.release()
cv2.destroyAllWindows()
