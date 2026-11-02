"""
model_layers.py -- custom Keras layers. Importing this module registers them
so that tf.keras.models.load_model() can deserialise saved models that use
them (see evaluate_model.py). The models built by ind_cpa.py do not use them.
"""
import tensorflow as tf


@tf.keras.utils.register_keras_serializable(package='custom')
class Slice(tf.keras.layers.Layer):
    """Slices a 2-D tensor along axis 1: output = x[:, start:stop]."""

    def __init__(self, start, stop, **kwargs):
        super().__init__(**kwargs)
        self.start = start
        self.stop = stop

    def call(self, x):
        return x[:, self.start:self.stop]

    def get_config(self):
        config = super().get_config()
        config.update({"start": self.start, "stop": self.stop})
        return config
