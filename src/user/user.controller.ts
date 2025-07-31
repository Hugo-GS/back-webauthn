import { Controller, Post, Body, Get, UseGuards, Request } from '@nestjs/common';
import { UserService } from './user.service';
import { User } from './user.entity';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RegisterUserDto } from '../dto/register-user.dto';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post('register')
  async register(@Body() userData: RegisterUserDto): Promise<User> {
    return this.userService.create(userData);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Request() req) {
    return this.userService.findOneById(req.user.userId);
  }
}
