#!/usr/bin/env python
# coding: utf-8
"""
ind_cpa.py -- train neural-network distinguishers between two ciphertext
classes (an IND-CPA style experiment).

Usage:
    python training/ind_cpa.py <config.json> <path/class0> <path/class1>

<path/classX> is the dataset prefix produced by datagen/generate_data.py; the
files <path/classX>_train and <path/classX>_validation are read. class0 gets
label 0, class1 label 1. A validation accuracy significantly above 0.5 means
the network can distinguish the two classes.

Four architectures are trained one after another on the same data:
    small_*     2 x Dense(100)
    big_*       4 x Dense(600)
    s_resnet_*  3 x Dense(100) with one skip connection
    l_resnet_*  5 x Dense(600) with two skip connections
For each, the following files are written to the current directory, named
<prefix><class0 name>_<timestamp>_<config name>:
    .h5                   best model (lowest validation loss)
    _training_log.csv     per-epoch metrics
    _history.npy          Keras history dict

Set USE_GPU=0 in the environment to train on the CPU. Otherwise the script
requires a GPU and enables mixed precision.
"""
import gc
import os
import sys
from datetime import datetime
import numpy as np
import tensorflow as tf
import json
from tensorflow.keras.optimizers import SGD
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense, Flatten, Add
from tensorflow.keras.callbacks import ModelCheckpoint, CSVLogger, EarlyStopping, ReduceLROnPlateau
from sklearn.preprocessing import MinMaxScaler
from crypto_import import import_hex_ciphers

# Configure GPU BEFORE importing TensorFlow operations
use_gpu_flag = os.environ.get("USE_GPU", "1")
if use_gpu_flag == "0":
    os.environ['CUDA_VISIBLE_DEVICES'] = '-1'
    print("GPU disabled by USE_GPU=0")
else:
    # Verify GPU availability
    print("\n" + "="*60)
    print("GPU CONFIGURATION CHECK")
    print("="*60)
    gpus = tf.config.list_physical_devices('GPU')
    print(f"Physical GPUs detected: {len(gpus)}")
    if not gpus:
        print("ERROR: No GPUs detected by TensorFlow!")
        print("This job REQUIRES GPU access but none are available.")
        print(f"TensorFlow version: {tf.__version__}")
        print(f"Built with CUDA: {tf.test.is_built_with_cuda()}")
        print("\nPossible causes:")
        print("1. TensorFlow installed without GPU support (tensorflow instead of tensorflow-gpu)")
        print("2. CUDA/cuDNN version mismatch with TensorFlow version")
        print("3. GPU drivers not loaded")
        print("\nExiting to prevent wasting cluster resources.")
        sys.exit(1)
    # Configure GPU memory growth
    try:
        for i, gpu in enumerate(gpus):
            tf.config.experimental.set_memory_growth(gpu, True)
            print(f"GPU {i}: {gpu.name} - Memory growth enabled")
    except RuntimeError as e:
        print(f"GPU configuration error: {e}")
        sys.exit(1)
    # Verify GPU is actually being used
    print(f"\nCUDA available: {tf.test.is_built_with_cuda()}")
    print(f"GPU devices available to TensorFlow: {tf.config.list_logical_devices('GPU')}")
    # Enable mixed precision for better GPU utilization
    tf.keras.mixed_precision.set_global_policy('mixed_float16')
    print("Mixed precision training enabled (FP16)")
    print("="*60 + "\n")
if len(sys.argv) != 4:
    print("Usage: python training/ind_cpa.py config path/class1 path/class2")
    sys.exit(1)
config_file = sys.argv[1]
class1_path = sys.argv[2]
class2_path = sys.argv[3]
# datestamp
datestamp_with_time = datetime.now().strftime('%Y%m%d%H%M%S')
# Environment and constants (see README.md for what each config key means)
with open(config_file, 'r') as f:
    config = json.load(f)
N_TRAIN = config["N_TRAIN"]
N_VALIDATE = config["N_VALIDATE"]
learning_rate = config["learning_rate"]
batch_size = config["batch_size"]
epochs = config["epochs"]
momentum = config["momentum"]
USE_BYTES = config["USE_BYTES"]
ES_delta = config["ES_delta"]
ES_patience= config["ES_patience"]
LR_delta = config["LR_delta"]
LR_patience= config["LR_patience"]
LR_factor = config["LR_factor"]
LR_min = config["LR_min"]
class1_name = os.path.basename(class1_path)
class2_name = os.path.basename(class2_path)
# Base name for all output files (written to the current directory).
output_file = f"{class1_name}_{datestamp_with_time}_{os.path.basename(config_file)}"
# Helper functions
def load_and_normalize_data(file_path, num_samples, bytemode, scaler=None):
    """
    Load and normalize cipher data. If no scaler is provided, a new scaler is created.
    """
    try:
        data = import_hex_ciphers(file_path, num_samples, bytemode=bytemode).astype(np.float32)
        if data is None:
            raise ValueError(f"import_hex_ciphers returned None for {file_path}")
        if scaler:
            data = scaler.transform(data).astype(np.float32)
        else:
            scaler = MinMaxScaler()
            data = scaler.fit_transform(data).astype(np.float32)
        return data, scaler
    except Exception as e:
        print(f"Error in loading data from {file_path}: {e}")
        sys.exit(1)  # Exit instead of returning None

def create_tf_dataset(data_a, data_b, labels_a, labels_b, batch_size, shuffle=True):
    """Concatenate both classes into one batched tf.data.Dataset."""
    X = np.concatenate((data_a, data_b), axis=0)
    Y = np.concatenate((labels_a, labels_b), axis=0).astype(np.float32)
    if shuffle:
        idx = np.random.permutation(len(X))
        X, Y = X[idx], Y[idx]
        del idx
    # Keep the dataset in host memory rather than on the GPU.
    with tf.device('/CPU:0'):
        dataset = tf.data.Dataset.from_tensor_slices((X, Y))
    del X, Y
    if shuffle:
        dataset = dataset.shuffle(buffer_size=10_000, reshuffle_each_iteration=True)
    return dataset.batch(batch_size).prefetch(tf.data.AUTOTUNE)

def build_small_model(input_shape):
    """
    Build a small neural network model for binary classification.
    """
    inputs = Input(shape=input_shape)
    x = Flatten()(inputs)
    x = Dense(100, activation='relu')(x)
    x = Dense(100, activation='relu')(x)
    # Use float32 for final layer (required for mixed precision)
    outputs = Dense(1, activation='sigmoid', dtype='float32')(x)
    model = Model(inputs=inputs, outputs=outputs)
    return model
def build_large_model(input_shape):
    """
    Build a larger neural network model for binary classification.
    """
    inputs = Input(shape=input_shape)
    x = Flatten()(inputs)
    for _ in range(4):
        x = Dense(600, activation='relu')(x)
    # Use float32 for final layer (required for mixed precision)
    outputs = Dense(1, activation='sigmoid', dtype='float32')(x)
    model = Model(inputs=inputs, outputs=outputs)
    return model

def build_small_resnet_model(input_shape):
    """
    Build a small neural network model for binary classification, with a
    skip connection from the first to the third hidden layer.
    """
    inputs = Input(shape=input_shape)
    x = Flatten()(inputs)
    layer1 = Dense(100, activation='relu')(x)
    layer2 = Dense(100, activation='relu')(layer1)
    layer3 = Dense(100, activation='relu')(layer2)
    layer3 = Add()([layer3, layer1])
    # Use float32 for final layer (required for mixed precision)
    outputs = Dense(1, activation='sigmoid', dtype='float32')(layer3)
    model = Model(inputs=inputs, outputs=outputs)
    return model

def build_large_resnet_model(input_shape):
    """
    Same as build_large_model, but with a skip connection every two layers.
    """
    inputs = Input(shape=input_shape)
    x = Flatten()(inputs)
    layer1 = Dense(600, activation='relu')(x)
    layer2 = Dense(600, activation='relu')(layer1)
    layer3 = Dense(600, activation='relu')(layer2)
    layer3 = Add()([layer3, layer1])
    layer4 = Dense(600, activation='relu')(layer3)
    layer5 = Dense(600, activation='relu')(layer4)
    x = Add()([layer5, layer3])
    # Use float32 for final layer (required for mixed precision)
    outputs = Dense(1, activation='sigmoid', dtype='float32')(x)
    model = Model(inputs=inputs, outputs=outputs)
    return model
def train_model(get_model_func, input_shape, train_data, val_data, epochs, save_name):
    """
    Train the given model and save weights and training history.
    """
    model = get_model_func(input_shape)
    model.compile(optimizer=SGD(learning_rate=learning_rate, momentum=momentum, nesterov=True),
                  loss='binary_crossentropy',
                  metrics=['accuracy'])
    model.summary()
    # Setup callbacks to save best model and logs
    callbacks = [
        ModelCheckpoint(f"{save_name}.h5", save_best_only=True, monitor='val_loss', mode='min', verbose=1),
        CSVLogger(f"{save_name}_training_log.csv", append=True),
        EarlyStopping(monitor='val_loss', patience=ES_patience, min_delta=ES_delta, restore_best_weights=True, verbose=1),
        ReduceLROnPlateau(monitor='val_loss', patience=LR_patience, factor=LR_factor, min_delta=LR_delta, min_lr=LR_min, verbose=1)
    ]
    # Train the model with tf.data.Dataset
    history = model.fit(
        train_data,
        epochs=epochs,
        validation_data=val_data,
        callbacks=callbacks
    )
    # Save training history
    np.save(f"{save_name}_history.npy", history.history)
    print(f"Training complete. Model and training history saved as {save_name}.h5 and {save_name}_history.npy.")
# Main script
print("\n" + "="*60)
print("VERIFYING GPU COMPUTATION")
print("="*60)
# Quick GPU test with actual computation
with tf.device('/GPU:0'):
    test_matrix = tf.random.normal([1000, 1000])
    result = tf.matmul(test_matrix, test_matrix)
    print(f"GPU test computation successful. Result shape: {result.shape}")
    print(f"Device used: {result.device}")
print("="*60 + "\n")
# The min-max scaler is fitted on the class-0 training data only and then
# reused for every other split, so all data is normalised identically.
print("Loading and normalizing training data...")
class1_train, scaler = load_and_normalize_data(class1_path + "_train", N_TRAIN, bytemode=USE_BYTES)
class2_train, _ = load_and_normalize_data(class2_path + "_train", N_TRAIN, bytemode=USE_BYTES, scaler=scaler)
print(f"Training data shapes: class1={class1_train.shape}, class2={class2_train.shape}")
# Generate scalar labels for binary classification (0 = class1, 1 = class2)
labels_train_0 = np.zeros(len(class1_train))
labels_train_1 = np.ones(len(class2_train))
# Create tf.data.Dataset objects (replaces generators)
print("Creating TensorFlow datasets...")
input_shape = class1_train.shape[1:]
train_dataset = create_tf_dataset(class1_train, class2_train,
                                   labels_train_0, labels_train_1,
                                   batch_size=batch_size)
del class1_train, class2_train, labels_train_0, labels_train_1
gc.collect()

# Test data is loaded only after the (larger) training arrays are freed above,
# so the two splits never sit fully resident in memory at the same time --
# on large-record ciphers (e.g. HQC) that overlap alone was enough to OOM.
# (Despite the "test" naming, this is the _validation split; the _test split
# is held out for training/evaluate_model.py.)
print("Loading and normalizing test data...")
class1_test, _ = load_and_normalize_data(class1_path + "_validation", N_VALIDATE, bytemode=USE_BYTES, scaler=scaler)
class2_test, _ = load_and_normalize_data(class2_path + "_validation", N_VALIDATE, bytemode=USE_BYTES, scaler=scaler)
print(f"Test data shapes: class1={class1_test.shape}, class2={class2_test.shape}")
labels_test_0 = np.zeros(len(class1_test))
labels_test_1 = np.ones(len(class2_test))
val_dataset = create_tf_dataset(class1_test, class2_test,
                                labels_test_0, labels_test_1,
                                batch_size=batch_size, shuffle=False)
del class1_test, class2_test, labels_test_0, labels_test_1
gc.collect()

# Train small model
print("\n" + "="*50)
print("Training Small Model")
print("="*50)
train_model(build_small_model, input_shape, train_dataset, val_dataset,
            epochs=epochs, save_name="small_"+output_file)
# Train large model
print("\n" + "="*50)
print("Training Large Model")
print("="*50)
train_model(build_large_model, input_shape, train_dataset, val_dataset,
            epochs=epochs, save_name="big_"+output_file)

# Train small resnet model
print("\n" + "="*50)
print("Training Small ResNet Model")
print("="*50)
train_model(build_small_resnet_model, input_shape, train_dataset, val_dataset,
            epochs=epochs, save_name="s_resnet_"+output_file)

# Train large resnet model
print("\n" + "="*50)
print("Training Large ResNet Model")
print("="*50)
train_model(build_large_resnet_model, input_shape, train_dataset, val_dataset,
            epochs=epochs, save_name="l_resnet_"+output_file)
print("\nAll training complete!")
