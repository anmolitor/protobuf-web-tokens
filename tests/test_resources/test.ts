// @generated by protobuf-ts 2.9.4
// @generated from protobuf file "test_resources/test.proto" (package "test", syntax proto3)
// tslint:disable
import type { BinaryWriteOptions } from "@protobuf-ts/runtime";
import type { IBinaryWriter } from "@protobuf-ts/runtime";
import { WireType } from "@protobuf-ts/runtime";
import type { BinaryReadOptions } from "@protobuf-ts/runtime";
import type { IBinaryReader } from "@protobuf-ts/runtime";
import { UnknownFieldHandler } from "@protobuf-ts/runtime";
import type { PartialMessage } from "@protobuf-ts/runtime";
import { reflectionMergePartial } from "@protobuf-ts/runtime";
import { MessageType } from "@protobuf-ts/runtime";
/**
 * @generated from protobuf message test.Simple
 */
export interface Simple {
    /**
     * @generated from protobuf field: string some_claim = 2;
     */
    someClaim: string;
}
/**
 * @generated from protobuf message test.Complex
 */
export interface Complex {
    /**
     * @generated from protobuf field: int64 user_id = 1;
     */
    userId: bigint;
    /**
     * @generated from protobuf field: test.Nested nested = 2;
     */
    nested?: Nested;
    /**
     * @generated from protobuf field: string user_name = 3;
     */
    userName: string;
    /**
     * @generated from protobuf field: string email = 4;
     */
    email: string;
    /**
     * @generated from protobuf field: repeated test.Role roles = 5;
     */
    roles: Role[];
}
/**
 * @generated from protobuf message test.Nested
 */
export interface Nested {
    /**
     * @generated from protobuf field: int64 team_id = 1;
     */
    teamId: bigint;
    /**
     * @generated from protobuf field: string team_name = 2;
     */
    teamName: string;
}
/**
 * @generated from protobuf enum test.Role
 */
export enum Role {
    /**
     * @generated from protobuf enum value: ReadFeatureFoo = 0;
     */
    ReadFeatureFoo = 0,
    /**
     * @generated from protobuf enum value: WriteFeatureFoo = 1;
     */
    WriteFeatureFoo = 1,
    /**
     * @generated from protobuf enum value: ReadFeatureBar = 2;
     */
    ReadFeatureBar = 2,
    /**
     * @generated from protobuf enum value: WriteFeatureBar = 3;
     */
    WriteFeatureBar = 3
}
// @generated message type with reflection information, may provide speed optimized methods
class Simple$Type extends MessageType<Simple> {
    constructor() {
        super("test.Simple", [
            { no: 2, name: "some_claim", kind: "scalar", T: 9 /*ScalarType.STRING*/ }
        ]);
    }
    create(value?: PartialMessage<Simple>): Simple {
        const message = globalThis.Object.create((this.messagePrototype!));
        message.someClaim = "";
        if (value !== undefined)
            reflectionMergePartial<Simple>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: Simple): Simple {
        let message = target ?? this.create(), end = reader.pos + length;
        while (reader.pos < end) {
            let [fieldNo, wireType] = reader.tag();
            switch (fieldNo) {
                case /* string some_claim */ 2:
                    message.someClaim = reader.string();
                    break;
                default:
                    let u = options.readUnknownField;
                    if (u === "throw")
                        throw new globalThis.Error(`Unknown field ${fieldNo} (wire type ${wireType}) for ${this.typeName}`);
                    let d = reader.skip(wireType);
                    if (u !== false)
                        (u === true ? UnknownFieldHandler.onRead : u)(this.typeName, message, fieldNo, wireType, d);
            }
        }
        return message;
    }
    internalBinaryWrite(message: Simple, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        /* string some_claim = 2; */
        if (message.someClaim !== "")
            writer.tag(2, WireType.LengthDelimited).string(message.someClaim);
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message test.Simple
 */
export const Simple = new Simple$Type();
// @generated message type with reflection information, may provide speed optimized methods
class Complex$Type extends MessageType<Complex> {
    constructor() {
        super("test.Complex", [
            { no: 1, name: "user_id", kind: "scalar", T: 3 /*ScalarType.INT64*/, L: 0 /*LongType.BIGINT*/ },
            { no: 2, name: "nested", kind: "message", T: () => Nested },
            { no: 3, name: "user_name", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 4, name: "email", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 5, name: "roles", kind: "enum", repeat: 1 /*RepeatType.PACKED*/, T: () => ["test.Role", Role] }
        ]);
    }
    create(value?: PartialMessage<Complex>): Complex {
        const message = globalThis.Object.create((this.messagePrototype!));
        message.userId = 0n;
        message.userName = "";
        message.email = "";
        message.roles = [];
        if (value !== undefined)
            reflectionMergePartial<Complex>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: Complex): Complex {
        let message = target ?? this.create(), end = reader.pos + length;
        while (reader.pos < end) {
            let [fieldNo, wireType] = reader.tag();
            switch (fieldNo) {
                case /* int64 user_id */ 1:
                    message.userId = reader.int64().toBigInt();
                    break;
                case /* test.Nested nested */ 2:
                    message.nested = Nested.internalBinaryRead(reader, reader.uint32(), options, message.nested);
                    break;
                case /* string user_name */ 3:
                    message.userName = reader.string();
                    break;
                case /* string email */ 4:
                    message.email = reader.string();
                    break;
                case /* repeated test.Role roles */ 5:
                    if (wireType === WireType.LengthDelimited)
                        for (let e = reader.int32() + reader.pos; reader.pos < e;)
                            message.roles.push(reader.int32());
                    else
                        message.roles.push(reader.int32());
                    break;
                default:
                    let u = options.readUnknownField;
                    if (u === "throw")
                        throw new globalThis.Error(`Unknown field ${fieldNo} (wire type ${wireType}) for ${this.typeName}`);
                    let d = reader.skip(wireType);
                    if (u !== false)
                        (u === true ? UnknownFieldHandler.onRead : u)(this.typeName, message, fieldNo, wireType, d);
            }
        }
        return message;
    }
    internalBinaryWrite(message: Complex, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        /* int64 user_id = 1; */
        if (message.userId !== 0n)
            writer.tag(1, WireType.Varint).int64(message.userId);
        /* test.Nested nested = 2; */
        if (message.nested)
            Nested.internalBinaryWrite(message.nested, writer.tag(2, WireType.LengthDelimited).fork(), options).join();
        /* string user_name = 3; */
        if (message.userName !== "")
            writer.tag(3, WireType.LengthDelimited).string(message.userName);
        /* string email = 4; */
        if (message.email !== "")
            writer.tag(4, WireType.LengthDelimited).string(message.email);
        /* repeated test.Role roles = 5; */
        if (message.roles.length) {
            writer.tag(5, WireType.LengthDelimited).fork();
            for (let i = 0; i < message.roles.length; i++)
                writer.int32(message.roles[i]);
            writer.join();
        }
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message test.Complex
 */
export const Complex = new Complex$Type();
// @generated message type with reflection information, may provide speed optimized methods
class Nested$Type extends MessageType<Nested> {
    constructor() {
        super("test.Nested", [
            { no: 1, name: "team_id", kind: "scalar", T: 3 /*ScalarType.INT64*/, L: 0 /*LongType.BIGINT*/ },
            { no: 2, name: "team_name", kind: "scalar", T: 9 /*ScalarType.STRING*/ }
        ]);
    }
    create(value?: PartialMessage<Nested>): Nested {
        const message = globalThis.Object.create((this.messagePrototype!));
        message.teamId = 0n;
        message.teamName = "";
        if (value !== undefined)
            reflectionMergePartial<Nested>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: Nested): Nested {
        let message = target ?? this.create(), end = reader.pos + length;
        while (reader.pos < end) {
            let [fieldNo, wireType] = reader.tag();
            switch (fieldNo) {
                case /* int64 team_id */ 1:
                    message.teamId = reader.int64().toBigInt();
                    break;
                case /* string team_name */ 2:
                    message.teamName = reader.string();
                    break;
                default:
                    let u = options.readUnknownField;
                    if (u === "throw")
                        throw new globalThis.Error(`Unknown field ${fieldNo} (wire type ${wireType}) for ${this.typeName}`);
                    let d = reader.skip(wireType);
                    if (u !== false)
                        (u === true ? UnknownFieldHandler.onRead : u)(this.typeName, message, fieldNo, wireType, d);
            }
        }
        return message;
    }
    internalBinaryWrite(message: Nested, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        /* int64 team_id = 1; */
        if (message.teamId !== 0n)
            writer.tag(1, WireType.Varint).int64(message.teamId);
        /* string team_name = 2; */
        if (message.teamName !== "")
            writer.tag(2, WireType.LengthDelimited).string(message.teamName);
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message test.Nested
 */
export const Nested = new Nested$Type();