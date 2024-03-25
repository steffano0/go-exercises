package main

type Position struct {
	row int
	col int
}

type Rover struct {
	direction string
	position  *Position
}

type Obstacle struct {
	position *Position
}

type MarsRoverGame struct {
	rover     *Rover
	obstacles []*Obstacle
}

func (r *Rover) turnRight() {

	directions := map[string]string{
		"N": "E",
		"E": "S",
		"S": "W",
		"W": "N",
	}

	r.direction = directions[r.direction]
}

func (r *Rover) turnLeft() {
	directions := map[string]string{
		"N": "W",
		"W": "S",
		"S": "E",
		"E": "N",
	}

	r.direction = directions[r.direction]
}

func (g *MarsRoverGame) moveRoverForward() {

	positions := map[string][]int{
		"N": {g.rover.position.row - 1, g.rover.position.col},
		"E": {g.rover.position.row, g.rover.position.col + 1},
		"S": {g.rover.position.row + 1, g.rover.position.col},
		"W": {g.rover.position.row, g.rover.position.col - 1},
	}

	for _, v := range g.obstacles {
		if positions[g.rover.direction][0] == v.position.row && positions[g.rover.direction][1] == v.position.col {
			return
		}
	}

	g.rover.position.row = positions[g.rover.direction][0]
	g.rover.position.col = positions[g.rover.direction][1]
}

func (g *MarsRoverGame) setRover(direction string, position *Position) {
	g.rover = &Rover{direction: direction, position: position}
}

func (g *MarsRoverGame) setObstacles(obstacles []*Obstacle) {
	g.obstacles = obstacles

}
