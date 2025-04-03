from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import render, redirect
from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
from .EmailBackEnd import EmailBackEnd
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth import login as auth_login
from .models import *



def login_view(request):
    if request.method == "POST":
        user = EmailBackEnd.authenticate(request, username=request.POST.get('email'), password=request.POST.get('password'))
        if user is not None:
            auth_login(request, user)
            if user.is_superuser:
                return redirect('headoffice')
            elif user.groups.filter(name='Officers').exists():
                return redirect('officers')
            elif user.groups.filter(name='HQ').exists():
                return redirect('head_office')
            else:
                messages.error(request, "Invalid Login!")
                return render(request, 'login.html')
        else:
            messages.error(request, "Invalid Login Credentials!")
            return render(request, 'login.html')
    else:
        return render(request, 'login.html')
    



def logoutuser(request):
    logout(request)
    return redirect('login')

def officer_home(request):
    suspects = Person.objects.all()
    # paginator = Paginator(suspects, 10)  # Pagination to show 8 shops per page
    # page_number = request.GET.get('page')
    # page_obj = paginator.get_page(page_number)
    # user = request.user
   
    # context ={
    #     "page_obj" : page_obj
    # }
    # return render(request, 'hod_template/home_content.html', context)
    pass

from django.http import StreamingHttpResponse
import cv2
import dlib
import face_recognition
import os
from .models import Person

def video_feed(request):
    # Initialize dlib's face detector
    detector = dlib.get_frontal_face_detector()

    # Retrieve only persons of interest who are wanted
    wanted_persons = Person.objects.filter(wanted_status='yes')

    # Prepare lists for known face encodings and details
    known_faces = []
    known_details = []

    # Define the path to the video file
    current_directory = os.path.dirname(os.path.abspath(__file__))
    video_filename = 'troyy.mp4'
    video_path = os.path.join(current_directory, video_filename)

    # Load the face encodings for each wanted person
    for person in wanted_persons:
        image = face_recognition.load_image_file(person.photo.path)  # Assuming 'photo' field stores image path
        encoding = face_recognition.face_encodings(image)[0]
        known_faces.append(encoding)

        # Store details to be displayed when a face is recognized
        known_details.append({
            'name': person.name,
            'wanted_status': person.get_wanted_status_display(),
            'last_seen_location': person.last_seen_location,
        })

    # Open the video stream
    cap = cv2.VideoCapture(video_path)

    # Frame processing parameters
    frame_delay = 2  # Process every 2nd frame for smoother playback
    frame_count = 0
    detected_faces = []

    def frame_generator():
        nonlocal frame_count, detected_faces
        while True:
            ret, frame = cap.read()
            if not ret:
                # If the video has ended, reset the video stream to loop
                cap.open(video_path)
                continue

            # Resize frame to speed up processing
            frame = cv2.resize(frame, (1280, 720))

            # Process every 'frame_delay' frame
            if frame_count % frame_delay == 0:
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                faces = detector(gray)

                for face in faces:
                    x, y, w, h = face.left(), face.top(), face.width(), face.height()

                    # Encode the face in the current frame
                    current_face_encoding = face_recognition.face_encodings(frame, [(y, x + w, y + h, x)])[0]
                    matches = face_recognition.compare_faces(known_faces, current_face_encoding)

                    # If a match is found, retrieve the wanted person's details
                    if True in matches:
                        matched_index = matches.index(True)
                        person_details = known_details[matched_index]

                        # Draw a rectangle around the face and display the person's name and wanted status
                        cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 0, 255), 2)  # Red box for wanted person
                        text = f"{person_details['name']} (WANTED)"
                        text_size, _ = cv2.getTextSize(text, cv2.FONT_HERSHEY_SIMPLEX, 0.6, 2)
                        cv2.rectangle(frame, (x, y - 40 - text_size[1]), (x + w, y - 20), (255, 255, 255), cv2.FILLED)
                        cv2.putText(frame, text, (x, y - 30), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 0), 2, cv2.LINE_AA)

                        # Add detected face details to the list if not already present
                        if person_details not in detected_faces:
                            detected_faces.append(person_details)

            frame_count += 1

            # Encode the frame as a JPEG image
            ret, buffer = cv2.imencode('.jpg', frame)
            frame_bytes = buffer.tobytes()

            # Yield the frame bytes to be displayed in the browser
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

            # Send the detected faces list to the front-end (via JS)
            updateDetectedFacesJS(detected_faces)

    return StreamingHttpResponse(frame_generator(), content_type='multipart/x-mixed-replace; boundary=frame')





# JavaScript function for live updates (to be added in the template or a linked JS file)
"""
function updateDetectedFacesJS(detectedFaces) {
    const detectedList = document.getElementById('detected-faces');
    detectedList.innerHTML = '';  // Clear the current list

    detectedFaces.forEach(face => {
        let listItem = document.createElement('li');
        listItem.textContent = `Name: ${face.name}, Danger Level: ${face.wanted_status}, Last Location: ${face.last_seen_location}`;
        detectedList.appendChild(listItem);
    });
}
"""



def updateDetectedFacesJS(faces):
    # This will send the list of detected faces to the browser via JS.
    script = f"<script>updateDetectedFaces({faces})</script>"
    return script


