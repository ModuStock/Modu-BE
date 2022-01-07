package com.nklcb.kream.entity;

import static com.querydsl.core.types.PathMetadataFactory.*;

import com.querydsl.core.types.dsl.*;

import com.querydsl.core.types.PathMetadata;
import javax.annotation.processing.Generated;
import com.querydsl.core.types.Path;
import com.querydsl.core.types.dsl.PathInits;


/**
 * QLikes is a Querydsl query type for Likes
 */
@Generated("com.querydsl.codegen.DefaultEntitySerializer")
public class QLikes extends EntityPathBase<Likes> {

    private static final long serialVersionUID = 561099650L;

    private static final PathInits INITS = PathInits.DIRECT2;

    public static final QLikes likes = new QLikes("likes");

    public final NumberPath<Long> id = createNumber("id", Long.class);

    public final QKoreaStock koreaStock;

    public final QUsaStock usaStock;

    public final com.nklcb.kream.entity.security.QUser user;

    public QLikes(String variable) {
        this(Likes.class, forVariable(variable), INITS);
    }

    public QLikes(Path<? extends Likes> path) {
        this(path.getType(), path.getMetadata(), PathInits.getFor(path.getMetadata(), INITS));
    }

    public QLikes(PathMetadata metadata) {
        this(metadata, PathInits.getFor(metadata, INITS));
    }

    public QLikes(PathMetadata metadata, PathInits inits) {
        this(Likes.class, metadata, inits);
    }

    public QLikes(Class<? extends Likes> type, PathMetadata metadata, PathInits inits) {
        super(type, metadata, inits);
        this.koreaStock = inits.isInitialized("koreaStock") ? new QKoreaStock(forProperty("koreaStock")) : null;
        this.usaStock = inits.isInitialized("usaStock") ? new QUsaStock(forProperty("usaStock")) : null;
        this.user = inits.isInitialized("user") ? new com.nklcb.kream.entity.security.QUser(forProperty("user")) : null;
    }

}

