function solution(A) {
    const lastInArray = A[A.length - 1];
    let neg1 = -1;
    let result = neg1 * lastInArray;
    let sum = 0;
  
    for (let i = 0; i < A.length; i++) {
      sum += A[i];
    }
  
    let totalsum = sum + result;
    return totalsum;
  }
  
  module.exports = solution;
  
  // Example usage:
  let arr1 = [2, 1, -3, 4];
  console.log(solution(arr1)); // Example output
  
  let arr2 = [-4, 0, 3, -3];
  console.log(solution(arr2)); // Example output
  
  let arr3 = [1, 3, 2, 5];
  console.log(solution(arr3)); // Example output
  