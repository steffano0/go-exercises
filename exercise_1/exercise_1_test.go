package main

import (
	"testing"
)

func newFakeRover(d string) *Rover {
	return &Rover{direction: d, position: newFakeRoverPosition()}
}

func newFakeRoverPosition() *Position {
	return &Position{row: 2, col: 2}
}

func Test_Rover_roverSetsAttributesCorrectly(t *testing.T) {

	FakeRover := newFakeRover("N")
	FakeRoverPosition := newFakeRoverPosition()
	roverDirection := FakeRover.direction

	if roverDirection != "N" {
		t.Errorf("Rover direction = %s; want N", roverDirection)
	}

	roverPosition := FakeRover.position

	if roverPosition.col != FakeRoverPosition.col || roverPosition.row != FakeRoverPosition.row {
		t.Error("Rover position is incorrect")
	}

}

func Test_Rover_roverTurnRightWhenCurrentRoverDirectionIsNorth(t *testing.T) {

	FakeRover := newFakeRover("N")

	FakeRover.turnRight()

	roverDirection := FakeRover.direction

	if roverDirection != "E" {
		t.Errorf("Rover direction = %s; want E", roverDirection)
	}
}

func Test_Rover_roverTurnRightWhenCurrentRoverDirectionIsEast(t *testing.T) {

	FakeRover := newFakeRover("E")

	FakeRover.turnRight()

	roverDirection := FakeRover.direction

	if roverDirection != "S" {
		t.Errorf("Rover direction = %s; want S", roverDirection)
	}
}

func Test_Rover_roverTurnRightWhenCurrentRoverDirectionIsSouth(t *testing.T) {

	FakeRover := newFakeRover("S")

	FakeRover.turnRight()

	roverDirection := FakeRover.direction

	if roverDirection != "W" {
		t.Errorf("Rover direction = %s; want W", roverDirection)
	}
}

func Test_Rover_roverTurnRightWhenCurrentRoverDirectionIsWest(t *testing.T) {

	FakeRover := newFakeRover("W")

	FakeRover.turnRight()

	roverDirection := FakeRover.direction

	if roverDirection != "N" {
		t.Errorf("Rover direction = %s; want N", roverDirection)
	}
}

func Test_Rover_roverTurnLeftWhenCurrentRoverDirectionIsNorth(t *testing.T) {

	FakeRover := newFakeRover("N")

	FakeRover.turnLeft()

	roverDirection := FakeRover.direction

	if roverDirection != "W" {
		t.Errorf("Rover direction = %s; want W", roverDirection)
	}
}

func Test_Rover_roverTurnLeftWhenCurrentRoverDirectionIsWest(t *testing.T) {

	FakeRover := newFakeRover("W")

	FakeRover.turnLeft()

	roverDirection := FakeRover.direction

	if roverDirection != "S" {
		t.Errorf("Rover direction = %s; want S", roverDirection)
	}
}

func Test_Rover_roverTurnLeftWhenCurrentRoverDirectionIsSouth(t *testing.T) {

	FakeRover := newFakeRover("S")

	FakeRover.turnLeft()

	roverDirection := FakeRover.direction

	if roverDirection != "E" {
		t.Errorf("Rover direction = %s; want E", roverDirection)
	}
}

func Test_Rover_roverTurnLeftWhenCurrentRoverDirectionIsEast(t *testing.T) {

	FakeRover := newFakeRover("E")

	FakeRover.turnLeft()

	roverDirection := FakeRover.direction

	if roverDirection != "N" {
		t.Errorf("Rover direction = %s; want N", roverDirection)
	}
}

func Test_MarsRoverGame_createRover_setsARover(t *testing.T) {

	game := &MarsRoverGame{}

	game.setRover("", &Position{})

	if game.rover == nil {
		t.Error("Game rover is nil, expected *Rover")
	}
}

func Test_MarsRoverGame_setsObstacles(t *testing.T) {
	game := &MarsRoverGame{}

	game.setObstacles([]*Obstacle{{position: &Position{row: 4, col: 4}}})

	if game.obstacles == nil {
		t.Error("Obstacles is nil")
	}
}

func Test_MarsRoverGame_moveRoverForwardWhenCurrentRoverDirectionIsNorth(t *testing.T) {
	game := &MarsRoverGame{}

	game.setRover("N", &Position{row: 2, col: 2})

	game.moveRoverForward()

	nextRoverPosition := game.rover.position

	if nextRoverPosition.row != 1 || nextRoverPosition.col != 2 {
		t.Errorf("Rover position is %d,%d; want 1,2", nextRoverPosition.row, nextRoverPosition.col)
	}
}

func Test_MarsRoverGame_moveRoverForwardWhenCurrentRoverDirectionIsEast(t *testing.T) {
	game := &MarsRoverGame{}

	game.setRover("E", &Position{row: 2, col: 2})

	game.moveRoverForward()

	nextRoverPosition := game.rover.position

	if nextRoverPosition.row != 2 || nextRoverPosition.col != 3 {
		t.Errorf("Rover position is %d,%d; want 2,3", nextRoverPosition.row, nextRoverPosition.col)
	}
}

func Test_MarsRoverGame_moveRoverForwardWhenCurrentRoverDirectionIsSouth(t *testing.T) {
	game := &MarsRoverGame{}

	game.setRover("S", &Position{row: 2, col: 2})

	game.moveRoverForward()

	nextRoverPosition := game.rover.position

	if nextRoverPosition.row != 3 || nextRoverPosition.col != 2 {
		t.Errorf("Rover position is %d,%d; want 3,2", nextRoverPosition.row, nextRoverPosition.col)
	}
}

func Test_MarsRoverGame_moveRoverForwardWhenCurrentRoverDirectionIsWest(t *testing.T) {
	game := &MarsRoverGame{}

	game.setRover("W", &Position{row: 2, col: 2})

	game.moveRoverForward()

	nextRoverPosition := game.rover.position

	if nextRoverPosition.row != 2 || nextRoverPosition.col != 1 {
		t.Errorf("Rover position is %d,%d; want 2,1", nextRoverPosition.row, nextRoverPosition.col)
	}
}

func Test_MarsRoverGame_dontMoveForwardWhenHitObstacle(t *testing.T) {
	game := &MarsRoverGame{}

	game.setRover("N", &Position{row: 2, col: 2})

	game.setObstacles([]*Obstacle{{position: &Position{row: 1, col: 2}}})

	game.moveRoverForward()

	nextRoverPosition := game.rover.position

	if nextRoverPosition.row != 2 || nextRoverPosition.col != 2 {
		t.Errorf("Rover position is %d,%d; want 2,2", nextRoverPosition.row, nextRoverPosition.col)
	}

	game = &MarsRoverGame{}

	game.setRover("N", &Position{row: 2, col: 2})

	game.moveRoverForward()

	nextRoverPosition = game.rover.position

	if nextRoverPosition.row != 1 || nextRoverPosition.col != 2 {
		t.Errorf("Rover position is %d,%d; want 1,2", nextRoverPosition.row, nextRoverPosition.col)
	}

}
