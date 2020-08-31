CREATE TABLE "sessions" (
    "id" SERIAL PRIMARY KEY

  -- metadata
  , "created" TIMESTAMP NOT NULL
  , "uuid" VARCHAR NOT NULL

  -- content
  , "status" VARCHAR NOT NULL
);

CREATE UNIQUE INDEX "sessions_uuid" ON "sessions"("uuid");
