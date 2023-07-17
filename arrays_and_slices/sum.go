package main

func Sum(numbers []int) (sum int) {

	for _, number := range numbers {
		sum += number
	}
	return

}

func SumAll(numbersToSum ...[]int) []int {
	lengthOfNumbersToSum := len(numbersToSum)
	sums := make([]int, lengthOfNumbersToSum)

	for i, numbers := range numbersToSum {
		sums[i] = Sum(numbers)
	}

	return sums
}
