package org.example.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.*;

@Table(name = "PLANE")
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter
@Setter
public class Plane extends BaseObject{
    @Column(name = "NAME")
    private String name;

    @Column(name = "PRODUCER")
    private String producer;

    @Column(name = "DIAGRAM_LINK")
    private String diagramLink;

    @Column(name = "SUMMARY")
    private String summary;
}
