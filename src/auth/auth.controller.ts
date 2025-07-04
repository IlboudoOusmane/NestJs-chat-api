import { 
    Body,             
    Controller,      
    Get,              
    Post,             
    Request,        
    UseGuards        
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { RequestWithUser } from './jwt.strategy';
import { UserService } from 'src/user/user.service';

export type AuthBody = { email: string; password: string };
export type CreateUser = { name: string; email: string; password: string };

@Controller('auth')
export class AuthController {
    constructor( 
        private readonly authService: AuthService,
        private readonly userService: UserService
    ) {}

    // Permet à un utilisateur de se connecter
    @Post('login') 
    async login(@Body() authBody: AuthBody) {
        // Appelle le service d'authentification pour générer un token JWT
        return await this.authService.login({authBody});
    }

    // Permet de vérifier l'identité d'un utilisateur connecté (protégée par JWT)
    @UseGuards(JwtAuthGuard)
    @Get() 
    async authenticateUser (
        @Request() request: RequestWithUser  // Récupère l'utilisateur à partir du JWT
    ) {    
        // Utilise l'ID de l'utilisateur extrait du JWT pour récupérer ses infos complètes
        return await this.userService.getUser({
            userId: request.user.userId,
        });
    }

    // Permet d'enregistrer un nouvel utilisateur
    @Post('register') 
    async register(@Body() registerBody: CreateUser) {
        // Appelle le service d'authentification pour créer un nouvel utilisateur
        return await this.authService.register({registerBody});
    }
}
