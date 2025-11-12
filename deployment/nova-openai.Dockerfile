# InferX Nova-compatible Dockerfile
# This replaces vllm/vllm-openai with Nova's equivalent image
# All CLI arguments remain the same, only the command changes from 'vllm serve' to 'nova serve'

FROM remodlai/nova-openai:v0.2.98

WORKDIR /

# Upgrade the transformers library (same as vllm-opai.Dockerfile)
RUN apt-get -y update
RUN apt-get install libglib2.0-0 -y
RUN apt-get install libgl1 -y

RUN pip install --upgrade transformers
RUN pip install --upgrade safetensors
RUN pip install diffusers --upgrade
RUN pip install invisible_watermark accelerate

# Copy custom run scripts (for non-vLLM/Nova models)
COPY run_model.py /usr/lib/run_model.py
COPY run_stablediffusion.py /usr/lib/run_stablediffusion.py

# Note: The Nova OpenAI server is already configured and running
# It accepts the same arguments as vLLM:
#   --model, --trust-remote-code, --max-model-len, --tensor-parallel-size, etc.
# The only difference is the command: 'nova serve' instead of 'vllm serve'
