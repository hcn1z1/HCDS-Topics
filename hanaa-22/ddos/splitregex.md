# Report on "Regex generator"
## Introduction
This report explores the concepts of recurrent neural networks (**RNNs**), Long short-term
memory networks (**LSTMs**), regular expressions (**Regex**), and **SplitRegex**. It also examines their implementation in a DDoS attack mitigation system, detailing the reasons for choosing LSTMs and Regex, as well as the steps involved in implementing the model.

## Recurrent neural networks (RNNs)
Recurrent Neural Networks (**RNNs**) are suitable for processing sequential data, where the order of elements is important. They can store information about sequences of data and use it for predictions or classifications.

### Why use RNNs? 

RNNs are particularly suited for tasks where the order of elements is crucial, such as natural language processing (**NLP**), speech recognition, and text generation. Their ability to retain contextual information over multiple time steps makes them a powerful tool for these applications

### Operation of RNNs

RNNs have a recurrent loop that allows them to retain information from previous steps when processing current data. A typical RNN consists of three layers:
- Input layer : Receives sequential data at each time step.
- Hidden layer : Memorizes the previous state and combines it with the current input to compute the current hidden state.
- Output layer : Produces output for each step of the sequence based on the current hidden state

### Theory of RNNs

An RNN is designed to process data sequences using feedback loops. This means that the output of a node at a certain moment can affect the processing of data at future moments. The basic mathematical formula for calculating the hidden state at a given time **t** is:

h<sub>t</sub> = σ (W<sub>hh</sub> h<sub>t-1</sub> + W<sub>xh</sub> x<sub>t</sub> + b<sub>h</sub>)

**Where** :
- h<sub>t</sub> is the hidden state at time t.
- W<sub>hh</sub> is the weight of the previous hidden state.
- W<sub>xh</sub> is the weight of the input.
- x<sub>t</sub> is the input at time t.
- b<sub>h</sub> is the bias.
- σ is an activation function (like ReLU or tanh).

### Limitations of RNNs
- **Vanishing gradient** : During training on long sequences, gradients can become very small,
making it difficult to learn long-term relationships.
- **Exploding gradient** : Gradients can become very large, leading to unstable weight
updates

## Long short-term memory networks (LSTMs)
**LSTMs** are a variant of RNNs designed to address the long-term memory problem. They can handle long-term dependencies in data sequences, making them particularly suitable for classification and prediction tasks based on extended contexts.
### Why use LSTMs ?

**LSTMs** overcome the limitations of standard RNNs by solving the problems of vanishing and exploding gradients, making them more effective for learning long-term relationships in sequential data. Their ability to store and use information over long periods makes them particularly suitable for complex sequence processing tasks

### Operation of LSTMs
**LSTMs** have memory cells and control gates that regulate the flow of information:

LSTMs have memory cells and control gates that regulate the flow of information:

1. **Cell state** : The memory of the cell, which can carry information throughout the sequence
processing.
2. **Forget gate** : Decides which information in the cell should be discarded.
3. **Input gate** : Decides which new information should be stored in the cell.
4. **Output gate** : Decides which information from the cell should be output.

### Theory of LSTMs
LSTMs introduce three main gates: the input gate, the forget gate, and the output gate. These gates control the flow of information at each time step, helping to maintain stable gradients. The main formulas of LSTMs are:

- Forget gate: f<sub>t</sub> = σ (W<sub>f</sub> . [h<sub>t-1</sub>, x<sub>t</sub>] + b<sub>f</sub>)
- Input gate: i<sub>t</sub> = σ (W<sub>i</sub> . [h<sub>t-1</sub>, x<sub>t</sub>] + b<sub>i</sub>)
- Cell state update: C̅<sub>t</sub> = tanh(W<sub>C</sub> . [h<sub>t-1</sub>, x<sub>t</sub>] + b<sub>C</sub>)
- New cell state: C<sub>t</sub> = f<sub>t</sub> * C<sub>t-1</sub> + i<sub>t</sub> * C̅<sub>t</sub>
- Output gate: o<sub>t</sub> = σ (W<sub>o</sub> . [h<sub>t-1</sub>, x<sub>t</sub>] + b<sub>o</sub>)
- New hidden state: h<sub>t</sub> = o<sub>t</sub> * tanh(C<sub>t</sub>)

## Regular expressions (Regex)

Regular expressions are search patterns used to identify patterns in strings of characters.
They are crucial for detecting and filtering specific patterns, such as **SQL** injection attacks or **DDoS** attempts.

### Use of Regex in the project

Regex is used to detect malicious patterns in requests, allowing potential attacks to be filtered out before they reach the server

### Theory of Regex
Regular expressions use metacharacters to define search patterns. For example, the pattern `\d` matches any digit, and `\s` matches a whitespace character. Regex allows for very precise and flexible search criteria

### Example of Regex use

```python
import re
# Example Regex to detect GET requests
regex_get_request = r'GET\s/\S+\sHTTP/1\.1'

request = "GET /login HTTP/1.1"
if re.match(regex_get_request, request):
    print("GET request detected")
```


## SplitRegex

**SplitRegex** is a technique used to divide a complex regular expression into more
manageable subsets. This facilitates the maintenance and understanding of complex **regular expressions**, while allowing for better adaptation to changes in data schemas.

### Use of SplitRegex

SplitRegex is used to break down complex regular expressions into logical pieces, making them easier to manage and reuse in the DDoS attack mitigation project

## Regex generator

### What is a Regex generator ?
A Regex generator is a **crucial** tool in our **DDoS attack mitigation project**. It automatically generates **regular expressions** from given data or specific patterns, facilitating automated detection of malicious patterns in requests. This automation is critical for reducing human errors and **optimizing** the effectiveness of the filtering system.

### Techniques and Python libraries 
To implement a Regex generator, we can use Python libraries such as regexgen or refo. These libraries offer advanced features for generating regular expressions from input data, dynamically adapting patterns based on observed variations and behaviors in requests. Using these tools not only improves the accuracy of attack detection but also ensures simplified maintenance of complex regular expressions used in our system.

### Implementation schema of the model

**Data collection and preprocessing** :
- Retrieve malicious and legitimate DDoS request data for training and testing from (I will contact @ZeD_OnE HCn1).
 - Preprocess data by encoding it into numerical sequences.

**Regex generation**:
 - Use a Regex generator to create regular expressions matching malicious patterns.

**LSTM model creation and training** :
 - Define and compile the LSTM model.
 - Train the model with preprocessed data.

**Evaluation and integration** :
 - Evaluate the model on a test set.
 - Integrate the model into the mitigation system to monitor and filter malicious requests in real-time