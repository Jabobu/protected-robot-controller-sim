# NVIDIA Isaac Sim 6.0.0, linux/amd64 platform manifest from NVIDIA NGC.
# ROS build environment is also pinned; no mutable base tags are accepted.
FROM --platform=linux/amd64 ros:jazzy-ros-base@sha256:8eed0a4669bbf43ee331878a4c39bd8ebddea8e3312a58b4fae8edb14526b617 AS ros_build
SHELL ["/bin/bash", "-c"]
COPY ros2 /work/ros2
WORKDIR /work
RUN source /opt/ros/jazzy/setup.bash && colcon build --base-paths ros2 --install-base /opt/prc_ros

FROM --platform=linux/amd64 nvcr.io/nvidia/isaac-sim@sha256:a9d06fb72cc2b39b2bf1cacc002e9f7cd1a5bbe3c3cfbbcf2e6de3a1d726d101
USER root
COPY docker/requirements.lock /tmp/prc-requirements.lock
RUN /isaac-sim/python.sh -m pip install --no-cache-dir --only-binary=:all: --require-hashes --ignore-installed -r /tmp/prc-requirements.lock && rm /tmp/prc-requirements.lock
COPY --from=ros_build /opt/prc_ros /opt/prc_ros
COPY LICENSE /usr/share/licenses/prc-scene/LICENSE
LABEL org.opencontainers.image.base.name="nvcr.io/nvidia/isaac-sim:6.0.0" \
      org.opencontainers.image.base.digest="sha256:a9d06fb72cc2b39b2bf1cacc002e9f7cd1a5bbe3c3cfbbcf2e6de3a1d726d101" \
      org.prc-scene.image="1"
USER isaac-sim
