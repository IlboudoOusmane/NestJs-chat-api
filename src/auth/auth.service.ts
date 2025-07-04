import { Injectable } from '@nestjs/common';
import { AuthBody, CreateUser } from './auth.controller';
import { PrismaService } from 'src/prisma.service';
import { compare, hash } from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { UserPayload } from './jwt.strategy';

@Injectable()
export class AuthService {
    constructor( private readonly prisma: PrismaService, private readonly jwtService: JwtService) {}

    async login ({authBody}: {authBody: AuthBody}) {

        const {email, password} = authBody;

        const existingUser = await this.prisma.user.findUnique({
            where: {
                email,            },
        });

        if(!existingUser) {
            throw new Error("L'Utilisateur n'existe pas")
        }

        const isPasswordValid = await this.isPasswordValid({
            password,
            hashPassword: existingUser.password
        });

        if(!isPasswordValid) {
            throw new Error("Le Mot de passe est invalide") 
        }
        return this.authenticateUser({
            userId: existingUser.id
        });
        
    }

    private async hashPassword(
        {password}: {password: string}
    ) {
        const hashPassword = await hash(password,10)
        return hashPassword;
    }


    private async isPasswordValid({
        password, 
        hashPassword
    }: {
        password: string, 
        hashPassword: string
    }) {
        const isPasswordValid = await compare(password, hashPassword) 
        return isPasswordValid;
    }


    private async authenticateUser({userId}: UserPayload) {
        const payload: UserPayload = {userId};
        return {
            access_token: this.jwtService.sign(payload),
        };
    }


    async register ({registerBody}: { registerBody: CreateUser}) {

        const {name, email, password} = registerBody;

        const existingUser = await this.prisma.user.findUnique({
            where: {
                email,            },
        });

        if(existingUser) {
            throw new Error("Un compte existe déjà à cette adresse email")
        }
 
        const hashPassword = await this.hashPassword({password});
        
        const createdUser = await this.prisma.user.create({
            data: {
                name,
                email,
                password: hashPassword, 
            }
        })

        return this.authenticateUser({
            userId: createdUser.id,
        });
        
    }
    
}
