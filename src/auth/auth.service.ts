import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import * as bcrypt from 'bcrypt';
import { PrismaClient } from '@prisma/client';
import { RegisterUserDto } from './dto';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {

    private readonly logger = new Logger('AuthService');

    onModuleInit() {
        this.$connect();
        this.logger.log('MongoDb connected');
    }

    async registerUser(registerUserDto: RegisterUserDto) {
        try {
            const { email, password, name } = registerUserDto;
            const user = await this.user.findUnique({
                where: {
                    email
                }
            });

            if (user) {
                throw new RpcException({
                    status: 400,
                    message: 'User already exists'
                });
            }

            const newUser = await this.user.create({
                data: {
                    email,
                    password: bcrypt.hashSync(password, 10),
                    name: name
                }
            });

            return {
                user: newUser,
                token: 'token'
            };

        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            })
        }
    }

}
