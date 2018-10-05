package edu.uvu.cybersecurity.model;

public class UserData {
    private String name;

    public UserData(){};

    public UserData(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
