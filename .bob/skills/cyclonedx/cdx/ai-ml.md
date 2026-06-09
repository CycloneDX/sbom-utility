# `cdx:ai-ml` Namespace Taxonomy

This is the namespace for official CycloneDX properties specific to the Artificial Intelligence (AI) and Machine Learning (ML).

The official rules and processes apply - see [parent document](../cdx.md).

----

The following are the reserved namespaces for AI/ML under the `cdx:ai-ml` namespace.

| Namespace | Description |
| --------- | ----------- |
| [`cdx:ai-ml:model`](#cdxai-mlmodel-namespace-taxonomy) | Model-related properties. |
| [`cdx:ai-ml:tokenizer`](#cdxai-mltokenizer-namespace-taxonomy) | Tokenizer-related properties. |
| `cdx:ai-ml:prompt` | Prompt-related properties. |

_Boolean value_ are `true` or `false`; case sensitive.

---

## `cdx:ai-ml:model` Namespace Taxonomy

| Namespace | Description |
| --------- | ----------- |
| `cdx:ai-ml:model:modality` | Provide the modality/modalities the model supports. This describes the specific type(s) or format(s) of data the model is designed to process such as text, images, audio, video, or sensor data. |
| `cdx:ai-ml:model:template` | Mark a model as a template and describe its details. |
| `cdx:ai-ml:model:parameter` | Describe learned parameters of a model which dictated by the model's architecture and design before training. |
| `cdx:ai-ml:model:hyperparameter` | Describe parameters used to configure a model. |

### `cdx:ai-ml:model:modality` Namespace Taxonomy

Model modality values MUST be one of the following:

| Property | Description |
| -------- | ----------- |
| `cdx:ai-ml:model:modality:text` | Natural Language Processing (NLP) tasks and specializations such as Natural Language Understanding (NLU) for tasks like translation, summarization, conversation, classification and sentiment analysis. |
| `cdx:ai-ml:model:modality:code` | Specialized, text-based modality used for software engineering and logic. |
| `cdx:ai-ml:model:modality:instruct` | Specialized, text-based modality fine-tuned for understanding and executing natural language directives (i.e., instruction following). |
| `cdx:ai-ml:model:modality:image` (vision) | Image-based (i.e., computer vision) processing tasks used for object detection, generation, and classification as well as document processing. |
| `cdx:ai-ml:model:modality:video` | Video  processing tasks to extract structured information, including object detection, action recognition, scene detection, and temporal understanding. |
| `cdx:ai-ml:model:modality:audio` | Audio processing tasks such as Automatic Speech Recognition (ASR), Speech-to-Text, music generation, and sound pattern recognition. |
| `cdx:ai-ml:model:modality:sensor` (telemetry) |  Processes data from specialized sensors or hardware, such as LiDAR for autonomous vehicles or IoT sensor feeds. |
| `cdx:ai-ml:model:modality:biometric` | Specialized sensor-based modality used for analyzing biological traits for tasks such as facial recognition, fingerprint scanning, or voice authentication. |
| `cdx:ai-ml:model:modality:genomic` (telemetry) | Processes high-dimensional data used in drug discovery and medical research. |
| `cdx:ai-ml:model:modality:_undefined:<NAME>` | `<NAME>` placeholder, used to provide an arbitrary model modality name. |

#### Example: Using model modalities on the model's component

```jsonc
"component":
{
  "type": "machine-learning-model",
  "bom-ref": "pkg:huggingface/FakeAI/CoderModel",
  // ...,
  "properties": [
    {
      "name": "cdx:ai-ml:model:modality:code",
    },
    {
      "name": "cdx:ai-ml:model:modality:instruct",
    }
  ]
}
```

### `cdx:ai-ml:model:language` Namespace Taxonomy

Model language values MUST be valid [ISO 639-1 language codes](https://en.wikipedia.org/wiki/List_of_ISO_639_language_codes).

| Property | Description |
| -------- | ----------- |
| `cdx:ai-ml:model:language` | Describe what language(s) a model was trained for. Value MUST be of [ISO 639-1 language codes](https://en.wikipedia.org/wiki/List_of_ISO_639_language_codes). Value MUST be a single language code (e.g. `nl`) or a comma separated list of language codes (e.g. `en,fr,de,it,ja,zh`). </br> This property MAY occur multiple times. |

#### Example: Using multiple languages

```jsonc
{
  // ...
  "components": [{
    "type": "machine-learning-model",
    "name": "my model",
    "modelCard": {
      // ...
      "modelParameters": {
        "properties": [
          {
            "name": "cdx:ai-ml:model:language",
            "value": "de,en"
          },
          {
            "name": "cdx:ai-ml:model:language",
            "value": "la"
          },
          {
            "name": "cdx:ai-ml:model:language",
            "value": "it"
          }
        ]
      }
    }
  }]
}
```

### `cdx:ai-ml:model:template` Namespace Taxonomy

| Property | Description |
| -------- | ----------- |
| `cdx:ai-ml:model:template:prompt` | Mark a component as a model prompt template. _Boolean value_. </br> This property MAY appear once. |
| `cdx:ai-ml:model:template:chat` | Mark a component as a model chat template. _Boolean value_. </br> This property MAY appear once. |

### `cdx:ai-ml:model:parameter` Namespace Taxonomy

Model properties reflect on the methods used to control the model's parameter count, training or fine-tuning.

| Property | Description |
| -------- | ----------- |
| `cdx:ai-ml:model:parameter:count` | Total number of learned parameters for the model. This reflects the model's design and structure (e.g., number of layers in a neural network, nodes, and connectivity). </br> The value SHOULD use the industry-standard naming convention of number followed by one of the letters: `M` (Million), `B` (Billion) or `T` (Trillion). May appear once. |
| `cdx:ai-ml:model:parameter:tune_method` | Describes how the model was fine-tuned on or adapted to new data. This property MAY appear multiple times. Value SHOULD be of industry-standard keywords such as those [listed in the section below](#names-of-industry-standard-fine-tuning-methods). Value MUST be a single keyword (e.g., `lora`) or a comma separated list of keywords (e.g., `sft,rlhf`). </br> This property MAY occur multiple times. |
| `cdx:ai-ml:model:parameter:_undefined:<NAME>` | `<NAME>` placeholder, used to provide an arbitrary model parameter name. Arbitrarty value and meaning. |

#### Names of industry-standard fine-tuning methods

These following and similar values SHOULD be used on the `cdx:ai-ml:model:parameter:tune_method` parameter:

| Value | Description |
| ----- | ----------- |
| `full` | Updates all model parameters during tuning. |
| `sft` | Supervised Fine-Tuning. Uses labelled, human-curated data to train the model.|
| `rlhf` | Reinforcement Learning from Human Feedback. |
| `adapter` | Inserts small layers within the architecture which are tuned. |
| `prompt` | appends trainable parameters to the input embeddings |
| `lora` | Low-Rank Adaptation (LoRA). A standard Parameter-Efficient Fine-Tuning (PEFT) method. |
| `alora` | Allocating Low-Rank Adaptation (ALoRA). A standard Parameter-Efficient Fine-Tuning (PEFT) method. |
| `qlora` | Quantized low-rank adaptation (QLoRA). A standard Parameter-Efficient Fine-Tuning (PEFT) method. |

#### Example: Using model parameter names listed in the AI/ML taxonomy

The following pseudocode shows how you would include the defined (reserved) `count` and `tuning_method` model parameters on an ML model's model card:

```jsonc
{
  // ...
  "components": [{
    "type": "machine-learning-model",
    "name": "my model",
    "modelCard": {
      // ...
      "modelParameters": {
        "properties": [
          {
            "name": "cdx:ai-ml:model:parameter:count",
            "value": "7B"
          },
          {
            "name": "cdx:ai-ml:model:parameter:tuning_method",
            "value": "sft,rlhf"
          },
          {
            "name": "cdx:ai-ml:model:parameter:tuning_method",
            "value": "qlora"
          },
          {
            "name": "cdx:ai-ml:model:parameter:tuning_method",
            "value": "adapter"
          }
        ]
      }
    }
  }]
}
```

#### Example: Using an unlisted model parameter name

The following pseudocode shows how you would include a model parameter that is not currently listed in the AI/ML namespace taxonomy.  Below, we introduce the metasyntactic parameter name `foo` with a value `bar`.

```jsonc
{
  // ...
  "components": [{
    "type": "machine-learning-model",
    "name": "my model with own parameter",
    "modelCard": {
      // ...
      "modelParameters": {
        "properties": [
          {
            "name": "cdx:ai-ml:model:parameter:_undefined:foo",
            "value": "bar"
          }
        ]
      }
    }
  }]
}
```

### `cdx:ai-ml:model:hyperparameter` Namespace Taxonomy

Model hyperparameters are the settings used when configuring a model (and its algorithms) that determine how the model is structured and loaded into memory before any training or inference takes place.

Hyperparameters can vary widely depending on model architecture and specific model variants that reflect on the model's capabilities and specific code implementation. This means that we cannot exhaustively list all possible parameters as properties in a taxonomy; however, we intend the `cdx:ai-ml:model:hyperparameter` namespace to be extended with names that actually match the specific implementation, for which the property name placeholder `<NAME>` may be utilized.

Given that there are some commonly agreed-upon model configuration property names that are found in [Large Language Models (LLMs)](https://en.wikipedia.org/wiki/Large_language_model) that are implemented on a [Transformer](https://en.wikipedia.org/wiki/Transformer_(deep_learning)) architecture the following properties are defined for the `cdx:ai-ml:model:hyperparameter` namespace:

| Property | Description |
| -------- | ----------- |
| `cdx:ai-ml:model:hyperparameter:activation_dropout` | The regularization technique used during training that randomly masks (sets to zero) a percentage of the intermediate hidden state activations. |
| `cdx:ai-ml:model:hyperparameter:context_length` | The maximum number of tokens that the model can process at any one time. |
| `cdx:ai-ml:model:hyperparameter:hidden_act` | The activation function used on output values of the intermediate (hidden) layers of a neural network. The function transforms the raw, linear output into an activated output value that is passed to the next layer introducing non-linearity. It is industry-standard to reference these functions by short names such as ReLU (Rectified Linear Unit) or SiLU (Sigmoid Linear Unit) which SHOULD be encoded with the values `relu` and `silu` respectively. |
| `cdx:ai-ml:model:hyperparameter:hidden_size`, `:d_model` | The dimension of the input and output representations (i.e., of the token embeddings) used by the internal (hidden) layers of a model's neural network (e.g., `768`, `1024`, `4096`). |
| `cdx:ai-ml:model:hyperparameter:layer_norm_type` | The specific normalization technique used to stabilize training in a transformer model. It determines how the model rescales activation values to prevent gradients from exploding or vanishing (e.g., `RMSNorm`, `LayerNorm`, `Pre-LN`, `GroupNorm`, etc.). |
| `cdx:ai-ml:model:hyperparameter:num_hidden_layers`, `:num_layers` | The total number of intermediate (hidden) processing layers situated between the input layer and the output layer. The key `num_layers` is often used instead for non-transformer architectures (e.g., Recurrent Neural Networks (RNNs), Long Short-Term Memory (LSTM), etc.). |
| `cdx:ai-ml:model:hyperparameter:intermediate_size` | The number of "neurons" of the intermediate, hidden feed-forward layer within each Transformer block. This effectively describes the size of the "bottleneck" where the representation of the input data is expanded (typically 4 times the `hidden_size`) into a higher-dimensional space for processing before being projected back down to the main model hidden size. |
| `cdx:ai-ml:model:hyperparameter:layer_norm_epsilon` | The (very small) float value used in Transformer models which is added to the variance in the denominator of the layer normalization formula to prevent division by zero (e.g., `1e-06`, `1e-05`). |
| `cdx:ai-ml:model:hyperparameter:max_position_embeddings` | The maximum sequence/context length the model supports. |
| `cdx:ai-ml:model:hyperparameter:num_attention_heads` | The number of self-attention heads (e.g., `32`). |
| `cdx:ai-ml:model:hyperparameter:num_key_value_heads` | The number of attention heads used for the Key (K) and Value (V) projections in the attention mechanism of a transformer-based AI model. |
| `cdx:ai-ml:model:hyperparameter:quantization` | Defines the numerical precision (number of bits) used to store a model's weights (as tensors) (e.g., `bf16`, `q4_k_m`, `q8_0`, etc.). |
| `cdx:ai-ml:model:hyperparameter:tokenizer_class` | The specific software class (i.e., implementation) used to convert raw text into token IDs and back (e.g., `GPT2Tokenizer`, `LlamaTokenizer`, etc. ). |
| `cdx:ai-ml:model:hyperparameter:vocab_size` | The size of the token vocabulary. |
| `cdx:ai-ml:model:hyperparameter:_undefined:<NAME>` | `<NAME>` placeholder, used to provide an arbitrary model hyperparameter name. Arbitrarty value and meaning. |

Each well-known property MAY be used once.

#### Example: Using model hyperparameter names listed in the AI/ML taxonomy

The following pseudocode shows how you would include the defined (reserved) `hidden_act`, `hidden_size` and `num_hidden_layers` model hyperparameters on an ML model's model card:

```jsonc
{
  // ...
  "components": [{
    "type": "machine-learning-model",
    "name": "my model",
    // ...
    "modelCard": {
      "modelParameters": {
        "properties": [
          {
            "name": "cdx:ai-ml:model:hyperparameter:hidden_act",
            "value": "relu"
          },
          {
            "name": "cdx:ai-ml:model:parameter:hidden_size",
            "value": "4096"
          },
          {
            "name": "cdx:ai-ml:model:parameter:num_hidden_layers",
            "value": "32"
          }
        ]
      }
    }
  }]
}
```

#### Example: Using an unlisted model hyperparameter name

The following pseudocode shows how to include a model hyperparameter that is not currently listed in the AI/ML namespace taxonomy.  Below, we introduce the metasyntactic hyperparameter name `hamm` with a value `eggz`.

```jsonc
{
  // ...
  "components": [{
    "type": "machine-learning-model",
    "name": "my model with own hyperparameter",
    // ...
    "modelCard": {
      "modelParameters": {
        "properties": [
          {
            "name": "cdx:ai-ml:model:hyperparameter:_undefined:hamm",
            "value": "eggz"
          },
        ]
      }
    }
  }]
}
```

## `cdx:ai-ml:model:tokenizer` Namespace Taxonomy

| Property | Description |
| -------- | ----------- |

| `cdx:ai-ml:model:tokenizer` | Mark a component as a (model) tokenizer. _Boolean value_. </br> This property MAY appear once. |

---

## `cdx:ai-ml:tokenizer` Namespace Taxonomy

The following table lists the current set of namespaces in the `cdx:ai-ml:tokenizer` namespace:

| Namespace | Description |
| --------- | ----------- |
| `cdx:ai-ml:tokenizer:hyperparameter` | Describe a parameter used to configure a tokenizer. |

### `cdx:ai-ml:tokenizer:hyperparameter` Namespace Taxonomy

Model tokenizers, although generally conforming to small set of industry-acknowledged implementations, often have distinct variants developed to work with a specific model it was used to train.  These tokenizers have their own hyperparameters that can be declared as properties on a CycloneDX component's model card as described for `model:hyperparameter` (above).

Given that there are some commonly agreed-upon tokenizer configuration property names that are found in [Large Language Models (LLMs)](https://en.wikipedia.org/wiki/Large_language_model) that are implemented on a [Transformer](https://en.wikipedia.org/wiki/Transformer_(deep_learning)) architecture the following properties are defined for the `cdx:ai-ml:tokenizer:hyperparameter` namespace:

| Property | Description |
| -------- | ----------- |
| `cdx:ai-ml:tokenizer:hyperparameter:bos_token` | The Beginning-of-Sentence (BOS) token is a special token configured in a tokenizer that signifies the start of an input sequence. (e.g., `"<[end_of_text]>"`)|
| `cdx:ai-ml:tokenizer:hyperparameter:chat_template` | A string representation of the chat template that defines how to format conversational data using the configured tokenizer.|
| `cdx:ai-ml:tokenizer:hyperparameter:errors` | Configures how the tokenizer handles invalid UTF-8 byte sequences or character encoding issues when converting raw text into tokens. Known values include: `strict` (i.e., raise an error), `ignore` and `replace` (invalid token).|
| `cdx:ai-ml:tokenizer:hyperparameter:eos_token` | The End-of-Sentence (BOS) token is a special token configured in a tokenizer to act as a stop signal for text generation. |
| `cdx:ai-ml:tokenizer:hyperparameter:pad_token` | The pad token is a special token configured in a tokenizer to fill in empty spaces in shorter sequences within a batch, ensuring all input sequences have the exact same length. |
| `cdx:ai-ml:tokenizer:hyperparameter:padding_side` | Defines whether the tokenizer adds padding tokens (i.e., the `pad_token`) to the left or right side of a sequence to ensure all sequences in a batch are the same length. Known values are either `left` or `right`. |
| `cdx:ai-ml:tokenizer:hyperparameter:tokenizer_class` | The named tokenizer (class) implementation configured for the model when the tokenizer support multiple possible implementations. |
| `cdx:ai-ml:tokenizer:hyperparameter:unk_token` | The special token configured in a tokenizer to replace any input character or word that is not found in the model's vocabulary. |
| `cdx:ai-ml:tokenizer:hyperparameter:vocab_size` | The configured size of the token vocabulary. Please note this value SHOULD match the `vocab_size` model hyperparameter value if both are declared on the same model card. |
| `cdx:ai-ml:tokenizer:hyperparameter:_undefined:<NAME>` | `<NAME>` placeholder, used to provide an arbitrary tokenizer hyperparameter name. Arbitrarty value and meaning. |

Each well-known property MAY be used once, if not stated otherwise.

#### Tokenizer hyperparameter notes

* If the `cdx:ai-ml:model:hyperparameter:tokenizer_class` hyperparameter value is declared, the `cdx:ai-ml:tokenizer:hyperparameter:tokenizer_class` value SHOULD match.
* Tokenizer hyperparameter values should be compatible with the tokenizer class implementation (value) provided on the `tokenizer_class` hyperparameter.
* Tokenizer hyperparameters that configure special token such as `bos_token`, `eos_token`, `pad_token`, etc. often utilize a distinct syntax such as the `<|` and `|>` that delineates them from other tokens (e.g., `<|im_start|>`, `<|pad_id|>`, `<|end_of_text|>`).

#### Example: Using tokenizer hyperparameter names listed in the AI/ML taxonomy

The following pseudocode shows how you would include the defined (reserved) `eos_token` and `vocab_size` tokenizer hyperparameters on an ML model's model card:

```jsonc
{
  // ...
  "components": [{
    "type": "library",
    "name": "tokenization.py",
    // ...
    "properties": [
      {
          "name": "cdx:ai-ml:model:tokenizer",
          "value": "LLMTokenizer"
      },
      {
          "name": "cdx:ai-ml:tokenizer:hyperparameter:eos_token",
          "value": "<|end_of_text|>"
      },
      {
          "name": "cdx:ai-ml:tokenizer:parameter:vocab_size",
          "value": "152064"
      }
    ]
  }]
}
```

> **Note**: The `cdx:ai-ml:model:tokenizer` asserts (or tags) the associated component as a tokenizer with the implementation `LLMTokenizer` as the value before providing its hyperparameters.

#### Example: Using an unlisted tokenizer hyperparameter name

In the same way as shown in the model's `hyperparameter` example, the following pseudocode shows how you would include a tokenizer hyperparameter that is not currently listed in the AI/ML namespace taxonomy.  Below, we introduce the metasyntactic hyperparameter name `baz` with a value `qux`.

```jsonc
{
  // ...
  "components": [{
    "type": "library",
    "name": "tokenization.py",
    // ...
    "properties": [
      {
        "name": "cdx:ai-ml:model:tokenizer",
        "value": "LLMTokenizer"
      },
      {
        "name": "cdx:ai-ml:tokenizer:hyperparameter:_undefined:baz",
        "value": "qux"
      }
    ]
  }]
}
```
