'use strict';

function asciiFold(code) {
  return code >= 0x41 && code <= 0x5a ? code + 0x20 : code;
}

function digitRunEnd(text, start) {
  let index = start;
  while (index < text.length) {
    const code = text.charCodeAt(index);
    if (code < 0x30 || code > 0x39) break;
    index += 1;
  }
  return index;
}

function significantDigitStart(text, start, end) {
  let index = start;
  while (index < end - 1 && text.charCodeAt(index) === 0x30) index += 1;
  return index;
}

function compareDigitRuns(left, leftStart, leftEnd, right, rightStart, rightEnd) {
  const leftSignificant = significantDigitStart(left, leftStart, leftEnd);
  const rightSignificant = significantDigitStart(right, rightStart, rightEnd);
  const leftLength = leftEnd - leftSignificant;
  const rightLength = rightEnd - rightSignificant;
  if (leftLength !== rightLength) return leftLength < rightLength ? -1 : 1;
  for (let offset = 0; offset < leftLength; offset += 1) {
    const leftCode = left.charCodeAt(leftSignificant + offset);
    const rightCode = right.charCodeAt(rightSignificant + offset);
    if (leftCode !== rightCode) return leftCode < rightCode ? -1 : 1;
  }
  return 0;
}

function compareUtf8ThenCodeUnits(left, right) {
  if (left === right) return 0;
  const byteOrder = Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
  if (byteOrder !== 0) return byteOrder;
  const maximumLength = Math.max(left.length, right.length);
  for (let index = 0; index < maximumLength; index += 1) {
    const leftUnit = index < left.length ? left.charCodeAt(index) : -1;
    const rightUnit = index < right.length ? right.charCodeAt(index) : -1;
    if (leftUnit !== rightUnit) return leftUnit < rightUnit ? -1 : 1;
  }
  return 0;
}

// Runtime locale tables are not a durable ordering contract. This comparator
// implements the only locale behavior needed by the panel (ASCII case folding
// and numeric digit runs), then resolves every primary tie from the original
// bytes/code units. Its result is therefore independent of filesystem input
// order and the Node/ICU version used by a later process.
function compareNaturalStrings(leftValue, rightValue) {
  const left = String(leftValue ?? '');
  const right = String(rightValue ?? '');
  let leftIndex = 0;
  let rightIndex = 0;
  while (leftIndex < left.length && rightIndex < right.length) {
    const leftCode = left.charCodeAt(leftIndex);
    const rightCode = right.charCodeAt(rightIndex);
    const leftDigit = leftCode >= 0x30 && leftCode <= 0x39;
    const rightDigit = rightCode >= 0x30 && rightCode <= 0x39;
    if (leftDigit && rightDigit) {
      const leftEnd = digitRunEnd(left, leftIndex);
      const rightEnd = digitRunEnd(right, rightIndex);
      const digitOrder = compareDigitRuns(
        left,
        leftIndex,
        leftEnd,
        right,
        rightIndex,
        rightEnd,
      );
      if (digitOrder !== 0) return digitOrder;
      leftIndex = leftEnd;
      rightIndex = rightEnd;
      continue;
    }
    const leftFolded = asciiFold(leftCode);
    const rightFolded = asciiFold(rightCode);
    if (leftFolded !== rightFolded) return leftFolded < rightFolded ? -1 : 1;
    leftIndex += 1;
    rightIndex += 1;
  }
  if (leftIndex !== left.length || rightIndex !== right.length) {
    return leftIndex === left.length ? -1 : 1;
  }
  return compareUtf8ThenCodeUnits(left, right);
}

module.exports = {
  compareNaturalStrings,
  compareUtf8ThenCodeUnits,
};
