import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import * as bcrypt from 'bcrypt';
import { PrismaClient } from '@prisma/client';
import { LoginUserDto, RegisterUserDto } from './dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {

    private readonly logger = new Logger('AuthService');

    constructor(private readonly jwtService: JwtService) {
        super();
    }

    onModuleInit() {
        this.$connect();
        this.logger.log('MongoDb connected');
    }

    async verifyToken(token: string) {
        try {
            const { sub, iat, exp, ...user } = await this.jwtService.verifyAsync(token, {
                secret: envs.jwtSecret
            });
            return {
                user,
                token: await this.signJwt(user)
            };
        } catch (error) {
            throw new RpcException({
                status: 401,
                message: 'Invalid token'
            });
        }
    }

    async signJwt(payload: JwtPayload){
        return this.jwtService.signAsync(payload);
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

            const { password: _, ...rest } = newUser;

            return {
                user: rest,
                token: await this.signJwt(rest)
            };

        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            })
        }
    }

    async loginUser(loginUserDto: LoginUserDto) {
        try {
            const { email, password } = loginUserDto;
            const user = await this.user.findUnique({
                where: {
                    email
                }
            });

            if (!user) {
                throw new RpcException({
                    status: 400,
                    message: 'User/Password not valid'
                });
            }

            const isPasswordValid = bcrypt.compareSync(password, user.password);

            if( !isPasswordValid) {
                throw new RpcException({
                    status: 400,
                    message: 'User/Password not valid'
                });
            }

            const { password: _, ...rest } = user;

            return {
                user: rest,
                token: await this.signJwt(rest)
            };

        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            })
        }
    }
}
