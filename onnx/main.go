package main

import (
	"fmt"
	"io/ioutil"
	"log"

	"github.com/owulveryck/onnx-go"
	"github.com/owulveryck/onnx-go/backend/x/gorgonnx"
	"gorgonia.org/tensor"
)

func main() {
	// Create a backend receiver
	backend := gorgonnx.NewGraph()
	// Create a model and set the execution backend
	model := onnx.NewModel(backend)

	fmt.Println("1")
	// read the onnx model
	b, err := ioutil.ReadFile("./model-001.onnx_data")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("2")

	// Decode it into the model
	err = model.UnmarshalBinary(b)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("3")

	// Preprocess input text (replace this with your preprocessing code)
	inputTxt := "hello what's you're name"
	preprocessedData := preprocessText(inputTxt)

	// Transform preprocessed data to a tensor
	t := tensor.New(tensor.WithShape(1, int(len(preprocessedData))), tensor.Of(tensor.Float32), tensor.WithBacking(preprocessedData))

	// Set input tensor of the model
	model.SetInput(0, t)

	// Run inference
	err = backend.Run()
	if err != nil {
		log.Fatal(err)
	}

	// Get output tensors
	output, err := model.GetOutputTensors()
	if err != nil {
		log.Fatal(err)
	}

	// Write the first output to stdout
	fmt.Println(output[0])
}

// preprocessText should be replaced with your preprocessing function
func preprocessText(text string) []float32 {
	// Placeholder preprocessing code, replace with your actual preprocessing logic
	// This function should convert the input text into numerical features
	// and return them as a float32 slice.
	// For example, you might tokenize the text, convert tokens to embeddings,
	// and concatenate them into a single feature vector.
	return []float32{0.1, 0.2, 0.3} // Example placeholder output
}
