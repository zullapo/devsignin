import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { User } from './models/user.model';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { AuthService } from '../auth/auth.service';
import { SignupDto } from './dtos/signup.dto';
import { SigninDto } from './dtos/signin.dto';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel('User') private readonly usersModel: Model<User>,
    private readonly authService: AuthService,
  ) {}

  async signup(signupDto: SignupDto): Promise<User> {
    const user = new this.usersModel(signupDto);
    return user.save();
  }

  async signin(signinDto: SigninDto): Promise<UserWithToken> {
    const user = await this.findByEmail(signinDto.email);
    const match = await this.checkPassword(signinDto.password, user);
    if (!match) {
      throw new BadRequestException('Invalid credentials.');
    }
    const jwtToken = await this.authService.createAccessToken(user._id);
    return { name: user.name, email: user.email, jwtToken };
  }

  async findAll(): Promise<User[]> {
    return this.usersModel.find();
  }

  private async findByEmail(email: string): Promise<User> {
    const user = await this.usersModel.findOne({ email });
    if (!user) {
      throw new NotFoundException('E-mail not found.');
    }
    return user;
  }

  private async checkPassword(password: string, user: User): Promise<boolean> {
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      throw new BadRequestException('Password invalid');
    }
    return match;
  }
}
