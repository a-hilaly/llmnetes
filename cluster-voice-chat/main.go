package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"strings"
)

func readInput(input chan string) {
	for {
		var line string
		_, err := fmt.Scanf("%s\n", &line)
		if err != nil {
			panic(err)
		}
		input <- line
	}
}

func main() {
	hearCmd := exec.Command("hear")
	stdout, _ := hearCmd.StdoutPipe()

	// listen to text on stdin to start and stop recording
	// and print the text to stdout

	input := make(chan string)
	go readInput(input)
	for i := range input {
		switch i {
		case "start":
			err := hearCmd.Start()
			if err != nil {
				fmt.Println("error starting the command: ", err)
				close(input)
			}
		case "stop":
			err := hearCmd.Process.Kill()
			if err != nil {
				fmt.Println("error stopping the command: ", err)
			}
			close(input)
		}
	}

	allOutput := []string{}
	scanner := bufio.NewScanner(stdout)
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		m := scanner.Text()
		allOutput = append(allOutput, m)
	}
	// fmt.Println(getFullSentence(allOutput))
	myAudioInputFile := "my-audio-input.yaml"
	s, err := getFullSentence(allOutput)
	if err != nil {
		fmt.Println("error getting the full sentence: ", err)
		return
	}
	err = writeOutputToKubernetesCommandFile(myAudioInputFile, s)
	if err != nil {
		fmt.Println("error writing the output to kubernetes command file: ", err)
		return
	}

	kubectlCmd := exec.Command("kubectl", "apply", "-f", myAudioInputFile)
	kubectlCmd.Stdout = os.Stdout
	kubectlCmd.Stderr = os.Stderr
	kubectlCmd.Stdin = os.Stdin
	err = kubectlCmd.Run()
	if err != nil {
		fmt.Println("error running the command: ", err)
	}
}

func getFullSentence(allOutput []string) (string, error) {
	// traverse the array in reverse order and find the first
	// element that matches the last element.
	firstElement := allOutput[0]
	for i := len(allOutput) - 2; i >= 0; i-- {
		if allOutput[i] == firstElement {
			return strings.Join(allOutput[i+1:], " ") + ".", nil
		}
	}
	fmt.Println(allOutput)
	return fmt.Sprintf("ERROR: %+v", allOutput), fmt.Errorf("could not find the last element")
	return "ERROR", fmt.Errorf("could not find the last element")
}

func getFullSentence2(allOutput []string) (string, error) {
	// traverse the array in reverse order and find the first
	// element that matches the last element.
	lastElement := allOutput[len(allOutput)-1]
	for i := len(allOutput) - 2; i >= 0; i-- {
		if allOutput[i] == lastElement {
			return strings.Join(allOutput[i+1:], " ") + ".", nil
		}
	}
	fmt.Println(allOutput)
	fmt.Println(lastElement)
	return fmt.Sprintf("%+v", allOutput), fmt.Errorf("could not find the last element")
	return "ERROR", fmt.Errorf("could not find the last element")
}

// writeOutputToKubernetesCommandFile writes the output to a kubernetes command file
// that can be used to run the command in kubernetes.
/*
apiVersion: llmnetes.dev/v1alpha1
kind: Command
metadata:
	name: my-command
spec:
	input: INPUT
*/
func writeOutputToKubernetesCommandFile(filename, input string) error {
	content := fmt.Sprintf(`apiVersion: llmnetes.dev/v1alpha1
kind: CommandExec
metadata:
  name: my-command-%s
spec:
  input: %s`, randomString(5), input)
	return os.WriteFile(filename, []byte(content), 0644)
}

func randomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
